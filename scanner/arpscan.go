package scanner

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/log"
	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/kakeetopius/gscn/internal/notify"
	"github.com/kakeetopius/gscn/internal/route"
	"github.com/pterm/pterm"
)

type ARPScanner struct {
	ARPScanOptions
	results ARPScanResults
	logger  log.Logger
}

type ARPScanOptions struct {
	Targets             []netip.Prefix
	Interfaces          []netutil.Interface
	ResponseTimeout     time.Duration
	WithVendorInfo      bool
	HostNames           map[netip.Addr]string
	AddUnknownHostNames bool
	Workers             int
	MessageNotifier     notify.Notifier
}

type ARPScanResults struct {
	HostResults  []ARPHostResult `json:"results"`
	ARPScanStats `json:"stats"`
}

type ARPHostResult struct {
	IPAddr   netip.Addr `json:"ip"`
	MacAddr  MAC        `json:"mac"`
	HostName string     `json:"hostname"`
	Vendor   string     `json:"vendor"`
}

type ARPScanStats struct {
	PacketsSent     int           `json:"packets_sent"`
	PacketsReceived int           `json:"packets_received"`
	ScanDuration    time.Duration `json:"scan_duration"`
}

func NewARPScanner(opts ARPScanOptions) *ARPScanner {
	if opts.HostNames == nil {
		opts.HostNames = make(map[netip.Addr]string)
	}
	return &ARPScanner{
		ARPScanOptions: opts,
		results:        ARPScanResults{},
		logger:         log.NewLogger(true),
	}
}

func (s *ARPScanner) Scan() error {
	start := time.Now()
	hostResults, err := s.runArp()
	if err != nil {
		return err
	}
	stop := time.Now()

	s.results.HostResults = hostResults
	s.results.ScanDuration = stop.Sub(start)

	return s.addResultInfo()
}

func (s *ARPScanner) SendResultsViaNotifier() (err error) {
	if s.MessageNotifier == nil {
		return fmt.Errorf("arpscanner: no notifier is set")
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

func (s *ARPScanner) Results() ScanResults {
	return s.results
}

func (s *ARPScanner) PrintResults() {
	displayARPResults(&s.results, s.AddUnknownHostNames, s.WithVendorInfo)
}

func (s *ARPScanner) SetNotifier(n notify.Notifier) {
	s.MessageNotifier = n
}

func (s *ARPScanner) addResultInfo() error {
	results := s.results
	numHosts := len(results.HostResults)

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
	for i := range results.HostResults {
		if s.WithVendorInfo {
			results.HostResults[i].Vendor = netutil.MACVendor(results.HostResults[i].MacAddr.String())
		}
		if s.AddUnknownHostNames {
			results.HostResults[i].HostName = netutil.ReverseLookup(ctx, results.HostResults[i].IPAddr.String())
			bar.Increment()
		}
	}

	slices.SortFunc(results.HostResults, func(a, b ARPHostResult) int {
		return a.IPAddr.Compare(b.IPAddr)
	})

	return nil
}

func (r ARPScanResults) String() string {
	stringBuilder := strings.Builder{}

	tmpl := template.Must(template.New("arp_scan_results").Parse(ARPScanResultsTemplate))
	tmpl.Execute(&stringBuilder, r)

	return stringBuilder.String()
}

func (s *ARPScanner) runArp() ([]ARPHostResult, error) {
	if len(s.Targets) == 0 && len(s.Interfaces) == 0 {
		return nil, fmt.Errorf("please provide either an interface or targets to carry out an arp scan for")
	}

	if len(s.Targets) == 0 {
		for _, iface := range s.Interfaces {
			s.Targets = append(s.Targets, iface.IP4Addrs()...)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := s.ARPScanOptions

	resultsChan := make(chan []ARPHostResult)
	startSending := make(chan struct{})
	numHosts := netutil.HostsInIP4Network(opts.Targets)

	packetSender, err := NewPacketSender()
	if err != nil {
		return nil, err
	}
	defer packetSender.Close()

	packetReceiver, err := NewPacketReceiver(ctx, "arp", numHosts, s.Interfaces...)
	if err != nil {
		return nil, err
	}
	defer packetReceiver.Close()

	go getARPReplies(ctx, packetReceiver, s, resultsChan, startSending)

	<-startSending // wait for receiving routine to finish setup

	s.logger.Info("Probing host(s) on interface(s): " + getAllIfaceNames(opts.Interfaces))
	bar, err := pterm.DefaultProgressbar.WithTotal(int(numHosts)).Start()
	if err != nil {
		return nil, err
	}
	defer bar.Stop()

	router, err := route.NewRouter()
	if err != nil {
		return nil, err
	}

	for _, targetNet := range opts.Targets {
		ipToScan := targetNet.Masked().Addr() // first IP in range

		networkAddr := ipToScan
		broadCast := broadCastAddr(targetNet)

		iface, srcIP, err := router.Lookup(ipToScan)
		if err != nil {
			return nil, err
		}

		packetReceiver.AddReceivingInterface(iface)

		for targetNet.Contains(ipToScan) {
			if (ipToScan == networkAddr || ipToScan == broadCast) && !targetNet.IsSingleIP() {
				ipToScan = ipToScan.Next()
				continue
			}

			err = sendArpPacket(packetSender, &iface, srcIP, ipToScan)
			if err != nil {
				return nil, err
			}
			s.results.PacketsSent++
			bar.Increment()
			ipToScan = ipToScan.Next()
		}
	}

	s.logger.WaitTimeout(opts.ResponseTimeout, "response")
	cancel() // tell packet receiving routine to stop
	results := <-resultsChan

	return results, nil
}

func sendArpPacket(packetSender PacketSender, iface *netutil.Interface, srcIP, dstIP netip.Addr) error {
	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		Operation:       layers.ARPRequest,
		AddrType:        layers.LinkTypeEthernet,
		Protocol:        layers.EthernetTypeIPv4,
		HwAddressSize:   6,
		ProtAddressSize: 4,

		SourceHwAddress:   iface.HardwareAddr,
		SourceProtAddress: srcIP.AsSlice(),

		DstHwAddress:   net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress: dstIP.AsSlice(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}

	err := gopacket.SerializeLayers(buf, opts, eth, arp)
	if err != nil {
		return err
	}

	packetBytes := buf.Bytes()

	err = packetSender.SendPacket(packetBytes, iface)
	if err != nil {
		return err
	}
	return nil
}

func getARPReplies(ctx context.Context, packetReceiver PacketReceiver, scanner *ARPScanner, resultsChan chan<- []ARPHostResult, startSendChan chan<- struct{}) {
	opts := scanner.ARPScanOptions

	packetChan := packetReceiver.Packets()

	results := make([]ARPHostResult, 0, 15)
	receivedFrom := make(map[netip.Addr]struct{}) // to keep track of which IPs we have got replies from

	defer func() {
		resultsChan <- results
	}()

	startSendChan <- struct{}{}
	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packetChan:
			if !ok {
				return
			}
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arpPacket, ok := arpLayer.(*layers.ARP)
			if !ok {
				continue
			}
			if arpPacket.Operation != layers.ARPReply {
				continue
			}
			ipAddr, ok := netip.AddrFromSlice(arpPacket.SourceProtAddress)
			if !ok {
				continue
			}
			if !netutil.AddrIsPartOfNetworks(opts.Targets, &ipAddr) {
				// skip responses outside the specified network
				continue
			}
			scanner.results.PacketsReceived++
			_, alreadyReceived := receivedFrom[ipAddr]
			if alreadyReceived {
				continue
			}
			receivedFrom[ipAddr] = struct{}{}
			results = append(results, ARPHostResult{
				IPAddr:  ipAddr,
				MacAddr: MAC(arpPacket.SourceHwAddress),
			})
		}
	}
}

func broadCastAddr(networkPrefix netip.Prefix) netip.Addr {
	networkAddr := networkPrefix.Masked().Addr()
	hostBitLen := 32 - networkPrefix.Bits()

	ip := networkAddr.As4()

	ipUint := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	mask := uint32((1 << hostBitLen) - 1)

	broadCast := ipUint | mask

	return netip.AddrFrom4([4]byte{byte(broadCast >> 24), byte(broadCast >> 16), byte(broadCast >> 8), byte(broadCast)})
}

func displayARPResults(arpResults *ARPScanResults, withHostNames bool, withVendors bool) {
	if len(arpResults.HostResults) == 0 {
		fmt.Println()
		pterm.Info.Println("Host(s) not found on that network.")
	} else {
		fmt.Println()
		var tableData [][]string
		tableData = pterm.TableData{{"IP Address", "Mac Address"}}
		if withVendors {
			tableData[0] = append(tableData[0], "Vendor")
		}
		if withHostNames {
			tableData[0] = append(tableData[0], "HostNames")
		}

		for _, result := range arpResults.HostResults {
			row := []string{result.IPAddr.String(), result.MacAddr.String()}
			if withVendors {
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
	arpStats := arpResults.ARPScanStats
	fmt.Println("\nScan Duration:      ", arpStats.ScanDuration.Truncate(time.Millisecond))
	fmt.Println("Packets Sent:       ", arpStats.PacketsSent)
	fmt.Println("Packets Received:   ", arpStats.PacketsReceived)
	fmt.Println("Hosts Found:        ", len(arpResults.HostResults))
}

func getAllIfaceNames(ifaces []netutil.Interface) string {
	sb := strings.Builder{}
	for i, iface := range ifaces {
		if i != 0 {
			sb.WriteString(", ")
		}

		sb.WriteString(iface.Name)
	}

	return sb.String()
}
