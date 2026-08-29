package scanner

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/jsimonetti/rtnetlink/rtnl"
	"github.com/kakeetopius/gscn/internal/log"
	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/kakeetopius/gscn/internal/routing"
	"github.com/kakeetopius/gscn/packet"
	"github.com/pterm/pterm"
)

type ARPScanner struct {
	ARPScanOptions
	results        ARPScanResults
	logger         log.Logger
	ifaceProvider  netutil.NetInterfaceProvider
	router         routing.Router
	packetReceiver *packet.PcapPacketReceiver
	packetSender   packet.PacketSender
}

type ARPScanOptions struct {
	Targets             []netip.Prefix
	Interfaces          []netutil.Interface
	ResponseTimeout     time.Duration
	WithVendorInfo      bool
	HostNames           map[netip.Addr]string
	AddUnknownHostNames bool
	Verbose             bool
	Passive             bool
	ProbeCount          uint
	FromCache           bool
}

type ARPScanResults struct {
	HostResults  []ARPHostResult `json:"results"`
	ARPScanStats `json:"stats"`

	printHostNames bool `json:"-"`
	printVendors   bool `json:"-"`
}

type ARPHostResult struct {
	IPAddr   netip.Addr  `json:"ip"`
	MacAddr  netutil.MAC `json:"mac"`
	HostName string      `json:"hostname"`
	Vendor   string      `json:"vendor"`
}

type ARPScanStats struct {
	PacketsSent     int           `json:"packets_sent"`
	PacketsReceived int           `json:"packets_received"`
	ScanDuration    time.Duration `json:"scan_duration"`
}

func NewARPScanner(opts ARPScanOptions) (*ARPScanner, error) {
	if opts.HostNames == nil {
		opts.HostNames = make(map[netip.Addr]string)
	}
	ifaceProvider, err := netutil.InterfaceProvider()
	if err != nil {
		return nil, err
	}

	router, err := routing.NewRouter(ifaceProvider)
	if err != nil {
		return nil, err
	}
	return &ARPScanner{
		ARPScanOptions: opts,
		results:        ARPScanResults{},
		logger:         log.NewLogger(opts.Verbose),
		ifaceProvider:  ifaceProvider,
		router:         router,
	}, nil
}

func (s *ARPScanner) Scan(ctx context.Context) (ScanResults, error) {
	var err error

	start := time.Now()
	if s.FromCache {
		err = s.getNeighborsWithNetlink()
	} else {
		err = s.runArp(ctx)
	}
	if err != nil {
		return nil, err
	}

	s.results.ScanDuration = time.Since(start)

	err = s.processResults()
	if err != nil {
		return nil, err
	}

	return &s.results, nil
}

func (s *ARPScanner) processResults() error {
	results := s.results
	numHosts := len(results.HostResults)
	results.printHostNames = s.AddUnknownHostNames
	results.printVendors = s.WithVendorInfo

	var bar *pterm.ProgressbarPrinter
	var err error
	if s.AddUnknownHostNames && numHosts > 0 {
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

	s.results = results

	return nil
}

func (r *ARPScanResults) Print() {
	r.display()
}

func (r *ARPScanResults) String() string {
	stringBuilder := strings.Builder{}

	tmpl := template.Must(template.New("arp_scan_results").Parse(ARPScanResultsTemplate))
	tmpl.Execute(&stringBuilder, r)

	return stringBuilder.String()
}

func (s *ARPScanner) runArp(ctx context.Context) error {
	if len(s.Targets) == 0 && len(s.Interfaces) == 0 {
		return fmt.Errorf("please provide either an interface or targets to carry out an arp scan for")
	}

	if len(s.Targets) == 0 {
		for _, iface := range s.Interfaces {
			s.Targets = append(s.Targets, iface.IP4Addrs()...)
		}
	}

	startSending := make(chan struct{})

	var packetSender packet.PacketSender
	var err error
	if runtime.GOOS == "linux" {
		packetSender, err = packet.GetPacketSender(ctx, packet.PacketSenderTypeLinkLayer)
	} else {
		packetSender, err = packet.GetPacketSender(ctx, packet.PacketSenderTypePcap)
	}
	if err != nil {
		return err
	}
	defer packetSender.Close()
	s.packetSender = packetSender

	packetReceiver, err := packet.NewPacketReceiver(ctx, "arp", 1024, s.Interfaces...)
	if err != nil {
		return err
	}
	defer packetReceiver.Close()
	s.packetReceiver = packetReceiver

	receiverDone := make(chan struct{})
	go s.getARPReplies(ctx, startSending, receiverDone)

	<-startSending // wait for receiving routine to finish setup

	if !s.Passive {
		err = s.sendARPProbes()
		if err != nil {
			return err
		}
		packetSender.Wait() // wait for packet sender to send all packets
	}

	s.logger.WaitTimeout(s.ResponseTimeout, "response")
	packetReceiver.Close()

	<-receiverDone // wait for receiving routine to finish
	close(receiverDone)

	return nil
}

func (s *ARPScanner) sendARPProbes() error {
	if len(s.Interfaces) != 0 {
		s.logger.Info("Probing host(s) on interface(s): " + joinIfaceNames(s.Interfaces))
	}

	numHosts := netutil.HostsInIP4Network(s.Targets)

	var err error
	bar := pterm.DefaultProgressbar.WithTotal(int(numHosts))
	if s.Verbose {
		bar, err = bar.Start()
		if err != nil {
			return err
		}
		defer bar.Stop()
	}

	for _, targetNet := range s.Targets {
		ipToScan := targetNet.Masked().Addr() // first IP in range

		networkAddr := ipToScan
		broadCast := ip4broadCastAddr(targetNet)

		route, err := s.router.Lookup(ipToScan)
		if err != nil {
			return err
		}

		s.packetReceiver.AddReceivingInterface(route.Interface)

		for targetNet.Contains(ipToScan) {
			if (ipToScan == networkAddr || ipToScan == broadCast) && !targetNet.IsSingleIP() {
				ipToScan = ipToScan.Next()
				continue
			}

			for range s.ProbeCount {
				err = sendArpPacket(s.packetSender, &route.Interface, route.SrcAddr, ipToScan)
				if err != nil {
					return err
				}
				s.results.PacketsSent++
			}
			bar.Increment()
			ipToScan = ipToScan.Next()
		}
	}

	return nil
}

func sendArpPacket(packetSender packet.PacketSender, iface *netutil.Interface, srcIP, dstIP netip.Addr) error {
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

func (s *ARPScanner) getNeighborsWithNetlink() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("getting ipv4 neighbour information from the kernel is only available on linux for now")
	}

	results := make([]ARPHostResult, 0, 5)

	conn, err := rtnl.Dial(nil)
	if err != nil {
		return fmt.Errorf("failed to establish connection to netlink subsystem: %v", err)
	}
	defer conn.Close()

	for _, iface := range s.Interfaces {
		neighbours, err := conn.Neighbours(&iface.Interface, syscall.AF_INET)
		if err != nil {
			return err
		}
		for _, neigh := range neighbours {
			addr, ok := netip.AddrFromSlice(neigh.IP)
			if !ok {
				continue
			}
			if neigh.Interface.Index != iface.Index {
				continue
			}
			if addr.IsMulticast() {
				continue
			}
			if netutil.MAC(neigh.HwAddr).IsBroadCast() {
				continue
			}

			results = append(results, ARPHostResult{
				IPAddr:  addr,
				MacAddr: netutil.MAC(neigh.HwAddr),
				Vendor:  netutil.MACVendor(neigh.HwAddr.String()),
			})
		}
	}
	s.results.HostResults = results

	return nil
}

func (s *ARPScanner) getARPReplies(ctx context.Context, startSendChan chan<- struct{}, receiverDone chan<- struct{}) {
	opts := s.ARPScanOptions

	packetChan := s.packetReceiver.Packets()

	results := make([]ARPHostResult, 0, 15)
	receivedFrom := make(map[netip.Addr]struct{}) // to keep track of which IPs we have got replies from

	defer func() {
		s.results.HostResults = results
		receiverDone <- struct{}{}
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
			s.results.PacketsReceived++
			_, alreadyReceived := receivedFrom[ipAddr]
			if alreadyReceived {
				continue
			}
			receivedFrom[ipAddr] = struct{}{}
			results = append(results, ARPHostResult{
				IPAddr:  ipAddr,
				MacAddr: netutil.MAC(arpPacket.SourceHwAddress),
			})
		}
	}
}

func (r ARPScanResults) display() {
	fmt.Println()
	var tableData [][]string
	tableData = pterm.TableData{{"IP Address", "Mac Address"}}
	if r.printVendors {
		tableData[0] = append(tableData[0], "Vendor")
	}
	if r.printHostNames {
		tableData[0] = append(tableData[0], "HostNames")
	}

	for _, result := range r.HostResults {
		row := []string{result.IPAddr.String(), result.MacAddr.String()}
		if r.printVendors {
			vendor := cmp.Or(result.Vendor, "(unknown)")
			row = append(row, vendor)
		}
		if r.printHostNames {
			hostName := cmp.Or(result.HostName, "(unknown)")
			row = append(row, hostName)
		}
		tableData = append(tableData, row)
	}

	if len(r.HostResults) == 0 {
		fmt.Println()
		pterm.Info.Println("No IPv4 hosts found")
	} else {
		pterm.DefaultTable.
			WithHasHeader().
			WithHeaderRowSeparator("-").
			WithBoxed().
			WithData(tableData).
			Render()
	}

	fmt.Println("\nScan Duration:      ", r.ScanDuration.Truncate(time.Millisecond))
	fmt.Println("Packets Sent:       ", r.PacketsSent)
	fmt.Println("Packets Received:   ", r.PacketsReceived)
	fmt.Println("Hosts Found:        ", len(r.HostResults))
}
