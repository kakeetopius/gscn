package scanner

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jsimonetti/rtnetlink/rtnl"
	"github.com/kakeetopius/gscn/internal/log"
	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/kakeetopius/gscn/internal/notify"
	"github.com/pterm/pterm"
)

type NDPScanner struct {
	NDPScanOptions
	results NDPScanResults
	logger  log.Logger
}

type NDPScanOptions struct {
	Targets             []netip.Prefix
	Source              netip.Addr
	Interface           netutil.Interface
	ResponseTimeout     time.Duration
	HostNames           map[netip.Addr]string
	WithVendorInfo      bool
	WithHostNames       bool
	AddUnknownHostNames bool
	FromCache           bool
	Workers             int
	MessageNotifier     notify.Notifier
}

type NDPScanResults struct {
	HostResults  []NDPHostResult `json:"results"`
	NDPScanStats `json:"stats"`
}

type NDPHostResult struct {
	IPAddr   netip.Addr `json:"ip"`
	MacAddr  string     `json:"mac"`
	HostName string     `json:"hostname"`
	Vendor   string     `json:"vendor"`
}

type NDPScanStats struct {
	PacketsSent     int           `json:"packets_sent"`
	PacketsReceived int           `json:"packets_received"`
	ScanDuration    time.Duration `json:"scan_duration"`
}

func NewNDPScanner(opts NDPScanOptions) *NDPScanner {
	if opts.HostNames == nil {
		opts.HostNames = make(map[netip.Addr]string)
	}
	return &NDPScanner{
		NDPScanOptions: opts,
		results:        NDPScanResults{},
		logger:         log.NewLogger(true),
	}
}

func (s *NDPScanner) Scan() error {
	start := time.Now()

	var hostResults []NDPHostResult
	var err error

	if s.FromCache {
		hostResults, err = ndpResultsUsingNetlink(&s.Interface, s.Targets)
	} else {
		hostResults, err = s.runNDP()
	}

	if err != nil {
		return err
	}
	stop := time.Now()

	s.results.HostResults = hostResults
	s.results.ScanDuration = stop.Sub(start)

	return s.addResultInfo()
}

func (s *NDPScanner) SendResultsViaNotifier() error {
	if s.MessageNotifier == nil {
		return fmt.Errorf("ndpscanner: no notifier is set")
	}
	spinner, err := pterm.DefaultSpinner.Start("Sending Results....")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			spinner.Fail()
		} else {
			spinner.Success("Results Sent")
		}
	}()

	err = s.MessageNotifier.SendMessage(s.results.String())
	if err != nil {
		return err
	}

	return nil
}

func (s *NDPScanner) PrintResults() {
	displayNDPResults(&s.results, s.WithVendorInfo, s.AddUnknownHostNames)
}

func (s *NDPScanner) Results() ScanResults {
	return s.results
}

func (s *NDPScanner) SetNotifier(n notify.Notifier) {
	s.MessageNotifier = n
}

func (s *NDPScanner) addResultInfo() error {
	resultSet := s.results
	numHosts := len(resultSet.HostResults)

	var bar *pterm.ProgressbarPrinter
	var err error
	if s.AddUnknownHostNames {
		fmt.Println()
		s.logger.Info("Trying to resolve hostnames")
		bar, err = pterm.DefaultProgressbar.WithTotal(numHosts).Start()
		if err != nil {
			return err
		}
		defer bar.Stop()
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.ResponseTimeout)
	defer cancel()
	for i := range resultSet.HostResults {
		if s.WithVendorInfo {
			resultSet.HostResults[i].Vendor = netutil.MACVendor(resultSet.HostResults[i].MacAddr)
		}
		if s.AddUnknownHostNames {
			resultSet.HostResults[i].HostName = netutil.ReverseLookup(ctx, resultSet.HostResults[i].IPAddr.String())
			bar.Increment()
		}
	}

	slices.SortFunc(resultSet.HostResults, func(a, b NDPHostResult) int {
		return a.IPAddr.Compare(b.IPAddr)
	})
	return nil
}

func (r NDPScanResults) String() string {
	stringBuilder := strings.Builder{}

	tmpl := template.Must(template.New("ndp_scan_results").Parse(NDPScanResultsTemplate))
	tmpl.Execute(&stringBuilder, r)

	return stringBuilder.String()
}

func (s *NDPScanner) runNDP() ([]NDPHostResult, error) {
	opts := s.NDPScanOptions
	resultChan := make(chan []NDPHostResult)
	startSending := make(chan struct{})
	errorChan := make(chan error)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go getNeighbourAdvertisements(ctx, s, resultChan, startSending, errorChan)

outer:
	for {
		select {
		case err := <-errorChan:
			return nil, err
		case <-startSending:
			break outer
		}
	}
	s.logger.Info("Probing host on interface: " + opts.Interface.Name)

	packetSender, err := NewPacketSender()
	if err != nil {
		return nil, err
	}
	defer packetSender.Close()

	for _, target := range opts.Targets {
		IPaddr := target.Masked().Addr() // first IP in range
		for target.Contains(IPaddr) {
			err := sendNSPacket(s, packetSender, &IPaddr)
			if err != nil {
				return nil, err
			}
			IPaddr = IPaddr.Next()
		}
	}

	s.logger.WaitTimeout(opts.ResponseTimeout, "response")
	cancel() // tell packet receiving routine to stop
	results := <-resultChan
	return results, nil
}

func sendNSPacket(scanner *NDPScanner, packetSender PacketSender, dstIP *netip.Addr) error {
	iface := scanner.Interface
	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       solicitedNodeMacAddress(*dstIP),
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip := &layers.IPv6{
		SrcIP:      scanner.Source.AsSlice(),
		DstIP:      solicitedNodeIPAddress(*dstIP),
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
	}

	icmp := &layers.ICMPv6{
		TypeCode: layers.ICMPv6TypeNeighborSolicitation << 8, // typecode should be in first 8 bits of the 16 bit field
	}

	nd := &layers.ICMPv6NeighborSolicitation{
		TargetAddress: dstIP.AsSlice(),
		Options: layers.ICMPv6Options{
			layers.ICMPv6Option{
				Type: layers.ICMPv6OptSourceAddress,
				Data: iface.HardwareAddr,
			},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	icmp.SetNetworkLayerForChecksum(ip)
	err := gopacket.SerializeLayers(buf, options, eth, ip, icmp, nd)
	if err != nil {
		return err
	}

	packetBytes := buf.Bytes()

	err = packetSender.SendPacket(packetBytes, &iface)
	if err != nil {
		return err
	}
	scanner.results.PacketsSent++
	return nil
}

func getNeighbourAdvertisements(ctx context.Context, scanner *NDPScanner, resultsChan chan<- []NDPHostResult, startSendChan chan<- struct{}, errorChan chan<- error) {
	iface := scanner.Interface
	handle, err := pcap.OpenLive(iface.PcapName, 1600, false, time.Millisecond)
	if err != nil {
		errorChan <- err
		return
	}
	defer handle.Close()
	err = handle.SetBPFFilter("icmp6 and icmp6[0] == 136") // 136 is the number for ICMPv6TypeNeighborSolicitation
	if err != nil {
		errorChan <- err
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	hostResults := make([]NDPHostResult, 0, 15)

	startSendChan <- struct{}{}

	for {
		select {
		case <-ctx.Done():
			resultsChan <- hostResults
			return
		case packet, ok := <-packetChan:
			if !ok {
				continue
			}
			icmpLayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
			if icmpLayer == nil {
				continue
			}
			ip6layer := packet.Layer(layers.LayerTypeIPv6)
			ip6packet, ok := ip6layer.(*layers.IPv6)
			if !ok {
				continue
			}
			srcIP := netip.AddrFrom16([16]byte(ip6packet.SrcIP))
			if !netutil.AddrIsPartOfNetworks(scanner.Targets, &srcIP) {
				continue
			}
			scanner.results.PacketsReceived++
			icmpPacket, _ := icmpLayer.(*layers.ICMPv6NeighborAdvertisement)
			var hwAddr net.HardwareAddr
			for _, icmpOption := range icmpPacket.Options {
				if icmpOption.Type == layers.ICMPv6OptTargetAddress {
					hwAddr = net.HardwareAddr(icmpOption.Data)
					break
				}
			}

			var result NDPHostResult
			result.IPAddr = srcIP
			result.MacAddr = hwAddr.String()
			if icmpPacket.Router() {
				result.MacAddr = fmt.Sprintf("%v (router)", hwAddr)
			}
			hostResults = append(hostResults, result)
		}
	}
}

func ndpResultsUsingNetlink(iface *netutil.Interface, targets []netip.Prefix) ([]NDPHostResult, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("getting ipv6 neighbour information from the kernel is only available on linux for now")
	}
	results := make([]NDPHostResult, 0, 5)

	conn, err := rtnl.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to establish connection to netlink subsystem: %v", err)
	}
	defer conn.Close()

	neighbours, err := conn.Neighbours(&iface.Interface, syscall.AF_INET6)
	if err != nil {
		return nil, err
	}
	for _, neigh := range neighbours {
		addr, ok := netip.AddrFromSlice(neigh.IP)
		if !ok {
			continue
		}
		if netutil.AddrIsPartOfNetworks(targets, &addr) {
			results = append(results, NDPHostResult{
				IPAddr:  addr,
				MacAddr: neigh.HwAddr.String(),
				Vendor:  netutil.MACVendor(neigh.HwAddr.String()),
			})
		}
	}
	return results, nil
}

func solicitedNodeMacAddress(targetIP netip.Addr) net.HardwareAddr {
	// Format is 33:33:33:xx:xx:xx where xx:xx:xx is last 24 bits of the IPv6 Address
	addr := targetIP.As16()
	last24Bits := addr[13:16]

	return net.HardwareAddr{
		0x33, 0x33, 0x33,
		last24Bits[0],
		last24Bits[1],
		last24Bits[2],
	}
}

func solicitedNodeIPAddress(targetIP netip.Addr) net.IP {
	// Format is ff02::1:ffXX:xxxx where xx:xxxx is the last 24 bits of the IPv6 Address
	addr := targetIP.As16()
	last24Bits := addr[13:16]

	solIP := make(net.IP, 16)
	solIP[0] = 0xff
	solIP[1] = 0x02
	solIP[11] = 0x01
	solIP[12] = 0xff

	copy(solIP[13:16], last24Bits)
	return solIP
}

func displayNDPResults(ndpResults *NDPScanResults, withVendorInfo bool, withHostNames bool) {
	if len(ndpResults.HostResults) == 0 {
		fmt.Println()
		pterm.Info.Println("Host(s) not found on that network.")
	} else {
		fmt.Println()
		var tableData [][]string
		tableData = pterm.TableData{{"IP Address", "Mac Address"}}
		if withVendorInfo {
			tableData[0] = append(tableData[0], "Vendor")
		}
		if withHostNames {
			tableData[0] = append(tableData[0], "HostNames")
		}

		for _, result := range ndpResults.HostResults {
			row := []string{result.IPAddr.String(), result.MacAddr}
			if withVendorInfo {
				vendor := result.Vendor
				if vendor == "" {
					vendor = "(unknown)"
				}
				row = append(row, vendor)
			}
			if withHostNames {
				hostName := result.HostName
				if hostName == "" {
					hostName = "(unknown)"
				}
				row = append(row, hostName)
			}
			tableData = append(tableData, row)
		}
		pterm.DefaultTable.WithHasHeader().WithHeaderRowSeparator("*").WithBoxed().WithData(tableData).Render()
	}

	ndpStats := ndpResults.NDPScanStats

	fmt.Println("\nScan Duration:     ", ndpStats.ScanDuration.Truncate(time.Millisecond))
	fmt.Println("Packets Sent:      ", ndpStats.PacketsSent)
	fmt.Println("Packets Received:  ", ndpStats.PacketsReceived)
	fmt.Println("Hosts Found:       ", len(ndpResults.HostResults))
}
