package scanner

import (
	"context"
	"fmt"
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
	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/pterm/pterm"
)

type NDPScanner struct {
	*NDPScanOptions
	results NDPScanResults
	stats   NDPScanStats
	logger  log.Logger
}

type NDPScanOptions struct {
	Targets             []netip.Prefix
	Source              netip.Addr
	Interface           util.Interface
	ResponseTimeout     time.Duration
	HostNames           map[netip.Addr]string
	WithVendorInfo      bool
	WithHostNames       bool
	AddUnknownHostNames bool
	FromCache           bool
	Workers             int
	MessageNotifier     notifier.Notifier
}

type NDPScanResults struct {
	ResultSet    []NDPScanResult
	HasHostNames bool
	HasVendors   bool
}

type NDPScanResult struct {
	IPAddr   netip.Addr
	MacAddr  string
	HostName string
	Vendor   string
}

type NDPScanStats struct {
	PacketsSent     int
	PacketsReceived int
	ScanTime        time.Duration
}

func NewNDPScanner(opts *NDPScanOptions) *NDPScanner {
	if opts.HostNames == nil {
		opts.HostNames = make(map[netip.Addr]string)
	}
	return &NDPScanner{
		NDPScanOptions: opts,
		results:        NDPScanResults{},
		stats:          NDPScanStats{},
		logger:         log.NewLogger(true),
	}
}

func (s *NDPScanner) Scan() error {
	if s.NDPScanOptions == nil {
		return fmt.Errorf("no ndp options set yet")
	}
	start := time.Now()

	var results NDPScanResults
	var err error
	if s.FromCache {
		results, err = ndpResultsUsingNetlink(&s.Interface, s.Targets)
	} else {
		results, err = runIPv6Disc(s)
	}
	if err != nil {
		return err
	}

	stop := time.Now()
	s.results = results
	s.stats.ScanTime = stop.Sub(start)

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
	displayNDPResults(&s.results, &s.stats)
}

func (s *NDPScanner) Results() NDPScanResults {
	return s.results
}

func (s *NDPScanner) Stats() NDPScanStats {
	return s.stats
}

func (s *NDPScanner) addResultInfo() error {
	resultSet := s.results.ResultSet
	numHosts := len(resultSet)
	bar, err := pterm.DefaultProgressbar.WithTotal(numHosts).Start()
	if err != nil {
		return err
	}
	defer bar.Stop()

	if s.AddUnknownHostNames {
		s.results.HasHostNames = true
		fmt.Println()
		s.logger.Info("Trying to resolve hostnames")
	}
	if s.WithVendorInfo {
		s.results.HasVendors = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.ResponseTimeout)
	defer cancel()
	for i := range resultSet {
		if s.WithVendorInfo {
			resultSet[i].Vendor = util.MACVendor(resultSet[i].MacAddr)
		}
		if s.AddUnknownHostNames {
			resultSet[i].HostName = util.ReverseLookup(ctx, resultSet[i].IPAddr.String())
			bar.Increment()
		}
	}

	slices.SortFunc(resultSet, func(a, b NDPScanResult) int {
		return a.IPAddr.Compare(b.IPAddr)
	})
	return nil
}

func (r NDPScanResults) String() string {
	stringBuilder := strings.Builder{}
	fmt.Fprintln(&stringBuilder, "NDP Scan Results")

	for _, result := range r.ResultSet {
		fmt.Fprintf(&stringBuilder, "IP: %v\nMac: %v\nVendor: %v\nHostName: %v\n\n", result.IPAddr, result.MacAddr, result.Vendor, result.HostName)
	}

	return stringBuilder.String()
}

func runIPv6Disc(scanner *NDPScanner) (NDPScanResults, error) {
	opts := scanner.NDPScanOptions
	resultChan := make(chan NDPScanResults)
	startSending := make(chan struct{})
	errorChan := make(chan error)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go getNeighbourAdvertisements(ctx, scanner, resultChan, startSending, errorChan)

outer:
	for {
		select {
		case err := <-errorChan:
			return NDPScanResults{}, err
		case <-startSending:
			break outer
		}
	}
	scanner.logger.Info("Probing host on interface: " + opts.Interface.Name)

	for _, target := range opts.Targets {
		IPaddr := target.Masked().Addr() // first IP in range
		for target.Contains(IPaddr) {
			err := sendNSPacket(scanner, &IPaddr)
			if err != nil {
				return NDPScanResults{}, err
			}
			IPaddr = IPaddr.Next()
		}
	}

	scanner.logger.WaitTimeout(opts.ResponseTimeout, "response")
	cancel() // tell packet receiving routine to stop
	results := <-resultChan
	return results, nil
}

func sendNSPacket(scanner *NDPScanner, dstIP *netip.Addr) error {
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
		fmt.Println(err)
		return err
	}

	packetBytes := buf.Bytes()

	err = sendPacket(packetBytes, &iface)
	if err != nil {
		return err
	}
	scanner.stats.PacketsSent++
	return nil
}

func getNeighbourAdvertisements(ctx context.Context, scanner *NDPScanner, resultsChan chan<- NDPScanResults, startSendChan chan<- struct{}, errorChan chan<- error) {
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

	results := NDPScanResults{}
	startSendChan <- struct{}{}

	for {
		select {
		case <-ctx.Done():
			resultsChan <- results
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
			if !util.AddrIsPartOfNetworks(scanner.Targets, &srcIP) {
				continue
			}
			scanner.stats.PacketsReceived++
			icmpPacket, _ := icmpLayer.(*layers.ICMPv6NeighborAdvertisement)
			var hwAddr net.HardwareAddr
			for _, icmpOption := range icmpPacket.Options {
				if icmpOption.Type == layers.ICMPv6OptTargetAddress {
					hwAddr = net.HardwareAddr(icmpOption.Data)
					break
				}
			}

			var result NDPScanResult
			result.IPAddr = srcIP
			result.MacAddr = hwAddr.String()
			if icmpPacket.Router() {
				result.MacAddr = fmt.Sprintf("%v (router)", hwAddr)
			}
			results.ResultSet = append(results.ResultSet, result)
		}
	}
}

func ndpResultsUsingNetlink(iface *util.Interface, targets []netip.Prefix) (NDPScanResults, error) {
	if runtime.GOOS != "linux" {
		return NDPScanResults{}, fmt.Errorf("getting ipv6 neighbour information from the kernel is only available on linux for now")
	}
	results := NDPScanResults{
		ResultSet: make([]NDPScanResult, 0, 5),
	}
	conn, err := rtnl.Dial(nil)
	if err != nil {
		return NDPScanResults{}, fmt.Errorf("failed to establish connection to netlink subsystem: %v", err)
	}
	defer conn.Close()

	neighbours, err := conn.Neighbours(&iface.Interface, syscall.AF_INET6)
	if err != nil {
		return NDPScanResults{}, err
	}
	for _, neigh := range neighbours {
		addr, ok := netip.AddrFromSlice(neigh.IP)
		if !ok {
			continue
		}
		if util.AddrIsPartOfNetworks(targets, &addr) {
			results.ResultSet = append(results.ResultSet, NDPScanResult{
				IPAddr:  addr,
				MacAddr: neigh.HwAddr.String(),
				Vendor:  util.MACVendor(neigh.HwAddr.String()),
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

func displayNDPResults(ndpResults *NDPScanResults, ndpStats *NDPScanStats) {
	if len(ndpResults.ResultSet) == 0 {
		fmt.Println()
		pterm.Info.Println("Host(s) not found on that network.")
	} else {
		fmt.Println()
		var tableData [][]string
		tableData = pterm.TableData{{"IP Address", "Mac Address"}}
		if ndpResults.HasVendors {
			tableData[0] = append(tableData[0], "Vendor")
		}
		if ndpResults.HasHostNames {
			tableData[0] = append(tableData[0], "HostNames")
		}

		for _, result := range ndpResults.ResultSet {
			row := []string{result.IPAddr.String(), result.MacAddr}
			if ndpResults.HasVendors {
				vendor := result.Vendor
				if vendor == "" {
					vendor = "(unknown)"
				}
				row = append(row, vendor)
			}
			if ndpResults.HasHostNames {
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

	if ndpStats != nil {
		fmt.Println("\nScan Duration:     ", ndpStats.ScanTime.Truncate(time.Millisecond))
		fmt.Println("Packets Sent:      ", ndpStats.PacketsSent)
		fmt.Println("Packets Received:  ", ndpStats.PacketsReceived)
		fmt.Println("Hosts Found:       ", len(ndpResults.ResultSet))
	}
}
