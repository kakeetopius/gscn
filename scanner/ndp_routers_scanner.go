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
	"text/template"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/log"
	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/kakeetopius/gscn/packet"
	"github.com/pterm/pterm"
)

type NDPRouterScanner struct {
	NDPRouterScannerOpts
	results        NDPScanResults
	logger         log.Logger
	ifaceProvider  netutil.NetInterfaceProvider
	packetSender   packet.PacketSender
	packetReceiver *packet.PcapPacketReceiver
}

type NDPRouterScannerOpts struct {
	Interfaces      []netutil.Interface
	ResponseTimeout time.Duration
	WithVendorInfo  bool
	AddHostNames    bool
	Passive         bool
	Workers         int
	Verbose         bool
	ProbeCount      uint
}

type NDPRouterScannerResults struct {
	HostResults  []NDPHostResult `json:"results"`
	NDPScanStats `json:"stats"`

	printHostNames bool `json:"-"`
	printVendors   bool `json:"-"`
}

func NewNDPRouterScanner(opts NDPRouterScannerOpts) (*NDPRouterScanner, error) {
	ifaceProvider, err := netutil.InterfaceProvider()
	if err != nil {
		return nil, err
	}

	return &NDPRouterScanner{
		NDPRouterScannerOpts: opts,
		results:              NDPScanResults{},
		logger:               log.NewLogger(opts.Verbose),
		ifaceProvider:        ifaceProvider,
	}, nil
}

func (s *NDPRouterScanner) Scan(ctx context.Context) (ScanResults, error) {
	start := time.Now()

	var err error

	err = s.runNDP(ctx)
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

func (s *NDPRouterScanner) processResults() error {
	s.results.printHostNames = s.AddHostNames
	s.results.printVendors = s.WithVendorInfo

	resultSet := s.results
	numHosts := len(resultSet.HostResults)

	var bar *pterm.ProgressbarPrinter
	var err error
	if s.AddHostNames && numHosts > 0 {
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
		if s.AddHostNames {
			resultSet.HostResults[i].HostName = netutil.ReverseLookup(ctx, resultSet.HostResults[i].IPAddr.String())
			bar.Increment()
		}
	}

	slices.SortFunc(resultSet.HostResults, func(a, b NDPHostResult) int {
		return a.IPAddr.Compare(b.IPAddr)
	})
	return nil
}

func (r *NDPRouterScannerResults) Print() {
	r.display()
}

func (r *NDPRouterScannerResults) String() string {
	stringBuilder := strings.Builder{}

	tmpl := template.Must(template.New("ndp_scan_results").Parse(NDPScanResultsTemplate))
	tmpl.Execute(&stringBuilder, r)

	return stringBuilder.String()
}

func (s *NDPRouterScanner) runNDP(ctx context.Context) error {
	if len(s.Interfaces) == 0 {
		ifaces, err := s.ifaceProvider.Interfaces()
		if err != nil {
			return err
		}
		for _, iface := range ifaces {
			err := netutil.VerifyInterface(&iface)
			if err == nil {
				s.Interfaces = append(s.Interfaces, iface)
			}
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

	packetReceiver, err := packet.NewPacketReceiver(ctx, "icmp6 and icmp6[0] == 134", 1024, s.Interfaces...) // 134 is type code for Router Advertisements
	if err != nil {
		return err
	}
	defer packetReceiver.Close()
	s.packetReceiver = packetReceiver

	receiverDone := make(chan struct{})
	go s.getRouterAdvertisements(ctx, startSending, receiverDone)

	<-startSending // wait for receiving routine to finish setup

	if !s.Passive {
		err := s.sendRSProbes()
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

func (s *NDPRouterScanner) sendRSProbes() error {
	s.logger.Info("Scanning for ipv6 routers on interface(s): " + joinIfaceNames(s.Interfaces))

	for _, iface := range s.Interfaces {
		ip6Addr, err := iface.FirstIP6Addr()
		if err != nil {
			return err
		}
		for range s.ProbeCount {
			err := sendRSPacket(s.packetSender, &iface, ip6Addr.Addr())
			if err != nil {
				return err
			}
			s.results.PacketsSent++
		}
	}

	return nil
}

func sendRSPacket(packetSender packet.PacketSender, iface *netutil.Interface, srcIP netip.Addr) error {
	dstIP := netip.MustParseAddr("ff02::2") // all ipv6 routers multicast address
	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       solicitedNodeMacAddress(dstIP),
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip := &layers.IPv6{
		SrcIP:      srcIP.AsSlice(),
		DstIP:      dstIP.AsSlice(),
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
	}

	icmp := &layers.ICMPv6{
		TypeCode: layers.ICMPv6TypeRouterSolicitation << 8, // typecode should be in first 8 bits of the 16 bit field
	}

	rd := &layers.ICMPv6RouterSolicitation{
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
	err := gopacket.SerializeLayers(buf, options, eth, ip, icmp, rd)
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

func (s *NDPRouterScanner) getRouterAdvertisements(ctx context.Context, startSendChan chan<- struct{}, receiverDone chan<- struct{}) {
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
			icmpLayer := packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
			if icmpLayer == nil {
				continue
			}
			ip6layer := packet.Layer(layers.LayerTypeIPv6)
			ip6packet, ok := ip6layer.(*layers.IPv6)
			if !ok {
				continue
			}
			srcIP := netip.AddrFrom16([16]byte(ip6packet.SrcIP))

			_, alreadyReceived := receivedFrom[srcIP]
			if alreadyReceived {
				continue
			}
			s.results.PacketsReceived++

			icmpPacket, _ := icmpLayer.(*layers.ICMPv6RouterAdvertisement)
			var hwAddr net.HardwareAddr
			for _, icmpOption := range icmpPacket.Options {
				if icmpOption.Type == layers.ICMPv6OptSourceAddress {
					hwAddr = net.HardwareAddr(icmpOption.Data)
					break
				}
			}

			result := NDPHostResult{
				IPAddr:  srcIP,
				MacAddr: netutil.MAC(hwAddr),
				Iface:   packet.Iface,
			}
			hostResults = append(hostResults, result)
			receivedFrom[srcIP] = struct{}{}
		}
	}
}

func (r NDPRouterScannerResults) display() {
	fmt.Println()
	var tableData [][]string
	tableData = pterm.TableData{{"IP Address", "Mac Address", "Iface"}}
	if r.printVendors {
		tableData[0] = append(tableData[0], "Vendor")
	}
	if r.printHostNames {
		tableData[0] = append(tableData[0], "HostNames")
	}

	for _, result := range r.HostResults {
		row := []string{result.IPAddr.String(), result.MacAddr.String(), result.Iface}

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
		pterm.Info.Println("No IPv6 routers found")
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
