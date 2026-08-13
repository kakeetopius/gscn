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
	"text/template"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/jsimonetti/rtnetlink/rtnl"
	"github.com/kakeetopius/gscn/internal/log"
	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/kakeetopius/gscn/internal/routing"
	"github.com/kakeetopius/gscn/packet"
	"github.com/pterm/pterm"
)

type NDPScanner struct {
	NDPScanOptions
	results        NDPScanResults
	logger         log.Logger
	ifaceProvider  netutil.NetInterfaceProvider
	router         routing.Router
	packetSender   packet.PacketSender
	packetReceiver *packet.PcapPacketReceiver
}

type NDPScanOptions struct {
	Targets             []netip.Prefix
	Interface           *netutil.Interface
	ResponseTimeout     time.Duration
	HostNames           map[netip.Addr]string
	WithVendorInfo      bool
	AddUnknownHostNames bool
	Passive             bool
	FromCache           bool
	Workers             int
	Verbose             bool
	ProbeCount          uint
}

type NDPScanResults struct {
	HostResults  []NDPHostResult `json:"results"`
	NDPScanStats `json:"stats"`

	printHostNames bool `json:"-"`
	printVendors   bool `json:"-"`
}

type NDPHostResult struct {
	IPAddr   netip.Addr  `json:"ip"`
	MacAddr  netutil.MAC `json:"mac"`
	HostName string      `json:"hostname"`
	Vendor   string      `json:"vendor"`
	IsRouter bool
}

type NDPScanStats struct {
	PacketsSent     int           `json:"packets_sent"`
	PacketsReceived int           `json:"packets_received"`
	ScanDuration    time.Duration `json:"scan_duration"`
}

func NewNDPScanner(opts NDPScanOptions) (*NDPScanner, error) {
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
	return &NDPScanner{
		NDPScanOptions: opts,
		results:        NDPScanResults{},
		logger:         log.NewLogger(opts.Verbose),
		ifaceProvider:  ifaceProvider,
		router:         router,
	}, nil
}

func (s *NDPScanner) Scan(ctx context.Context) (ScanResults, error) {
	start := time.Now()

	var err error

	if s.FromCache {
		err = s.getNeighborsWithNetlink()
	} else {
		err = s.runNDP(ctx)
	}

	if err != nil {
		return nil, err
	}
	stop := time.Now()

	s.results.ScanDuration = stop.Sub(start)

	err = s.addResultInfo()
	if err != nil {
		return nil, err
	}

	return &s.results, nil
}

func (s *NDPScanner) addResultInfo() error {
	s.results.printHostNames = s.AddUnknownHostNames
	s.results.printVendors = s.WithVendorInfo

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
			resultSet.HostResults[i].Vendor = netutil.MACVendor(resultSet.HostResults[i].MacAddr.String())
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

func (r *NDPScanResults) Print() {
	displayNDPResults(r, r.printVendors, r.printHostNames)
}

func (r *NDPScanResults) String() string {
	stringBuilder := strings.Builder{}

	tmpl := template.Must(template.New("ndp_scan_results").Parse(NDPScanResultsTemplate))
	tmpl.Execute(&stringBuilder, r)

	return stringBuilder.String()
}

func (s *NDPScanner) runNDP(ctx context.Context) error {
	if s.Interface == nil {
		return fmt.Errorf("please provide an interface to carry out an ndp scan on")
	}
	if len(s.Targets) == 0 {
		if !s.Passive {
			s.logger.Warn("No targets provided. Scanning of hosts on all the ipv6 subnets of the given interfaces which might take alot of time and resources.")
		}
		s.Targets = append(s.Targets, s.Interface.IP6Addrs()...)
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

	packetReceiver, err := packet.NewPacketReceiver(ctx, "icmp6 and icmp6[0] == 136", 1024, *s.Interface)
	if err != nil {
		return err
	}
	defer packetReceiver.Close()
	s.packetReceiver = packetReceiver

	receiverDone := make(chan struct{})
	go s.getNeighbourAdvertisements(ctx, startSending, receiverDone)

	<-startSending // wait for receiving routine to finish setup

	if !s.Passive {
		err := s.sendNSProbes()
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

func (s *NDPScanner) sendNSProbes() error {
	s.logger.Info("Probing host(s) on interface(s): " + s.Interface.Name)

	for _, target := range s.Targets {
		IPaddr := target.Masked().Addr() // first IP in range

		route, err := s.router.Lookup(IPaddr.WithZone(s.Interface.Name))
		if err != nil {
			return err
		}
		s.packetReceiver.AddReceivingInterface(route.Interface)

		for target.Contains(IPaddr) {
			for range s.ProbeCount {
				err := sendNSPacket(s.packetSender, &route.Interface, route.SrcAddr, IPaddr)
				if err != nil {
					return err
				}
				s.results.PacketsSent++
			}
			IPaddr = IPaddr.Next()
		}
	}

	return nil
}

func sendNSPacket(packetSender packet.PacketSender, iface *netutil.Interface, srcIP, dstIP netip.Addr) error {
	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       solicitedNodeMacAddress(dstIP),
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip := &layers.IPv6{
		SrcIP:      srcIP.AsSlice(),
		DstIP:      solicitedNodeIPAddress(dstIP),
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

	err = packetSender.SendPacket(packetBytes, iface)
	if err != nil {
		return err
	}
	return nil
}

func (s *NDPScanner) getNeighbourAdvertisements(ctx context.Context, startSendChan chan<- struct{}, receiverDone chan<- struct{}) {
	packetChan := s.packetReceiver.Packets()

	hostResults := make([]NDPHostResult, 0, 15)

	startSendChan <- struct{}{}

	receivedFrom := make(map[netip.Addr]struct{}) // to keep track of which IPs we have got replies from
	defer func() {
		s.results.HostResults = hostResults
		receiverDone <- struct{}{}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packetChan:
			if !ok {
				return
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

			if !netutil.AddrIsPartOfNetworks(s.Targets, &srcIP) {
				continue
			}

			_, alreadyReceived := receivedFrom[srcIP]
			if alreadyReceived {
				continue
			}
			s.results.PacketsReceived++

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
			result.MacAddr = netutil.MAC(hwAddr)
			if icmpPacket.Router() {
				result.IsRouter = true
			}
			hostResults = append(hostResults, result)
			receivedFrom[srcIP] = struct{}{}
		}
	}
}

func (s *NDPScanner) getNeighborsWithNetlink() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("getting ipv6 neighbour information from the kernel is only available on linux for now")
	}

	results := make([]NDPHostResult, 0, 5)

	conn, err := rtnl.Dial(nil)
	if err != nil {
		return fmt.Errorf("failed to establish connection to netlink subsystem: %v", err)
	}
	defer conn.Close()

	neighbours, err := conn.Neighbours(&s.Interface.Interface, syscall.AF_INET6)
	if err != nil {
		return err
	}
	for _, neigh := range neighbours {
		addr, ok := netip.AddrFromSlice(neigh.IP)
		if !ok {
			continue
		}
		if neigh.Interface.Index != s.Interface.Index {
			continue
		}
		if addr.IsMulticast() {
			continue
		}
		results = append(results, NDPHostResult{
			IPAddr:  addr,
			MacAddr: netutil.MAC(neigh.HwAddr),
			Vendor:  netutil.MACVendor(neigh.HwAddr.String()),
		})
	}
	s.results.HostResults = results

	return nil
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
		pterm.Info.Println("No hosts found")
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
			row := []string{result.IPAddr.String(), ""}
			if result.IsRouter {
				row[1] = fmt.Sprintf("%s (router)", result.MacAddr.String())
			} else {
				row[1] = result.MacAddr.String()
			}

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
