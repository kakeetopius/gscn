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

type NDPNeighborScanner struct {
	NDPNeighborScanOptions
	results        NDPScanResults
	logger         log.Logger
	ifaceProvider  netutil.NetInterfaceProvider
	router         routing.Router
	packetSender   packet.PacketSender
	packetReceiver packet.PacketReceiver
}

type NDPNeighborScanOptions struct {
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
	Iface    string      `json:"iface"`
	IsRouter bool        `json:"is_router"`
}

type NDPScanStats struct {
	PacketsSent     int           `json:"packets_sent"`
	PacketsReceived int           `json:"packets_received"`
	ScanDuration    time.Duration `json:"scan_duration"`
}

func NewNDPScanner(opts NDPNeighborScanOptions) (*NDPNeighborScanner, error) {
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
	return &NDPNeighborScanner{
		NDPNeighborScanOptions: opts,
		results:                NDPScanResults{},
		logger:                 log.NewLogger(opts.Verbose),
		ifaceProvider:          ifaceProvider,
		router:                 router,
	}, nil
}

func (s *NDPNeighborScanner) Scan(ctx context.Context) (ScanResults, error) {
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

	s.results.ScanDuration = time.Since(start)

	err = s.processResults(ctx)
	if err != nil {
		return nil, err
	}

	return &s.results, nil
}

func (s *NDPNeighborScanner) processResults(ctx context.Context) error {
	s.results.printHostNames = s.AddUnknownHostNames
	s.results.printVendors = s.WithVendorInfo
	if ctx.Err() != nil { // we have already been cancelled
		return nil
	}

	resultSet := s.results
	numHosts := len(resultSet.HostResults)

	if s.AddUnknownHostNames && numHosts > 0 {
		var bar *pterm.ProgressbarPrinter
		var err error

		fmt.Println()
		s.logger.Info("Trying to resolve hostnames")
		bar, err = pterm.DefaultProgressbar.WithTotal(numHosts).Start()
		if err != nil {
			return err
		}
		defer bar.Stop()

		newCtx, cancel := context.WithTimeout(ctx, s.ResponseTimeout)
		defer cancel()
		for i := range resultSet.HostResults {
			if ctx.Err() != nil {
				return nil
			}
			resultSet.HostResults[i].HostName = netutil.ReverseLookup(newCtx, resultSet.HostResults[i].IPAddr.String())
			bar.Increment()
		}
	}

	slices.SortFunc(resultSet.HostResults, func(a, b NDPHostResult) int {
		return a.IPAddr.Compare(b.IPAddr)
	})
	return nil
}

func (r *NDPScanResults) Print() {
	r.display()
}

func (r *NDPScanResults) String() string {
	stringBuilder := strings.Builder{}

	tmpl := template.Must(template.New("ndp_scan_results").Parse(NDPScanResultsTemplate))
	tmpl.Execute(&stringBuilder, r)

	return stringBuilder.String()
}

func (s *NDPNeighborScanner) runNDP(ctx context.Context) error {
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

	packetReceiver, err := packet.NewPacketReceiver(ctx, "icmp6 and icmp6[0] == 136", 1024, *s.Interface) // 136 is type code for Neighbor Advertisements
	if err != nil {
		return err
	}
	defer packetReceiver.Close()
	s.packetReceiver = packetReceiver

	receiverDone := make(chan struct{})
	go s.getNeighbourAdvertisements(ctx, startSending, receiverDone)

	<-startSending // wait for receiving routine to finish setup

	if !s.Passive {
		err := s.sendNSProbes(ctx)
		if err != nil {
			return err
		}
		packetSender.Wait() // wait for packet sender to send all packets
	}

	s.logger.WaitTimeout(ctx, s.ResponseTimeout, "response")
	packetReceiver.Close()

	<-receiverDone // wait for receiving routine to finish
	close(receiverDone)

	return nil
}

func (s *NDPNeighborScanner) sendNSProbes(ctx context.Context) error {
	s.logger.Info("Probing host(s) on interface(s): " + s.Interface.Name)

	for _, target := range s.Targets {
		IPaddr := target.Masked().Addr() // first IP in range

		route, err := s.router.Lookup(IPaddr.WithZone(s.Interface.Name))
		if err != nil {
			return err
		}
		s.packetReceiver.AddInterface(route.Interface)

		for target.Contains(IPaddr) {
			for range s.ProbeCount {
				if ctx.Err() != nil {
					return nil
				}
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

func (s *NDPNeighborScanner) getNeighbourAdvertisements(ctx context.Context, startSendChan chan<- struct{}, receiverDone chan<- struct{}) {
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

			result := NDPHostResult{
				IPAddr:   srcIP,
				MacAddr:  netutil.MAC(hwAddr),
				Iface:    packet.Iface,
				IsRouter: icmpPacket.Router(),
			}
			result.Vendor = netutil.MACVendor(result.MacAddr.String())
			hostResults = append(hostResults, result)
			receivedFrom[srcIP] = struct{}{}
		}
	}
}

func (s *NDPNeighborScanner) getNeighborsWithNetlink() error {
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

func (r NDPScanResults) display() {
	fmt.Println()
	var tableData [][]string
	tableData = pterm.TableData{{"IP Address", "Mac Address", "Interface"}}
	if r.printVendors {
		tableData[0] = append(tableData[0], "Vendor")
	}
	if r.printHostNames {
		tableData[0] = append(tableData[0], "HostName")
	}

	for _, result := range r.HostResults {
		row := []string{result.IPAddr.String(), "", result.Iface}
		if result.IsRouter {
			row[1] = fmt.Sprintf("%s (router)", result.MacAddr.String())
		} else {
			row[1] = result.MacAddr.String()
		}

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
		pterm.Info.Println("No IPv6 neighbors found")
	} else {
		pterm.DefaultTable.
			WithHasHeader().
			WithHeaderRowSeparator("-").
			WithBoxed().
			WithData(tableData).
			Render()
	}

	fmt.Println("\nScan Duration:     ", r.ScanDuration.Truncate(time.Millisecond))
	fmt.Println("Packets Sent:      ", r.PacketsSent)
	fmt.Println("Packets Received:  ", r.PacketsReceived)
	fmt.Println("Hosts Found:       ", len(r.HostResults))
}
