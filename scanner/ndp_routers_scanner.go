package scanner

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
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
	results        NDPRouterScannerResults
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
	RouterResults []NDPRouter `json:"routers"`
	NDPScanStats  `json:"stats"`

	printHostNames bool `json:"-"`
	printVendors   bool `json:"-"`
}

type NDPRouter struct {
	IPAddr      netip.Addr              `json:"ip"`
	MacAddr     netutil.MAC             `json:"mac"`
	HostName    string                  `json:"hostname"`
	Vendor      string                  `json:"vendor"`
	Iface       string                  `json:"iface"`
	Managed     bool                    `json:"managed"`
	OtherConfig bool                    `json:"other_config"`
	PrefixInfo  []IPv6PrefixInformation `json:"prefix_info"`
}

type IPv6PrefixInformation struct {
	Prefix            netip.Prefix  `json:"prefix"`
	OnLink            bool          `json:"on_link"`
	SLAACEnabled      bool          `json:"slaac_enabled"`
	ValidLifetime     time.Duration `json:"valid_lifetime"`
	PreferredLifetime time.Duration `json:"preferred_lifetime"`
}

func NewNDPRouterScanner(opts NDPRouterScannerOpts) (*NDPRouterScanner, error) {
	ifaceProvider, err := netutil.InterfaceProvider()
	if err != nil {
		return nil, err
	}

	return &NDPRouterScanner{
		NDPRouterScannerOpts: opts,
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
	numHosts := len(resultSet.RouterResults)

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
	for i := range resultSet.RouterResults {
		if s.WithVendorInfo {
			resultSet.RouterResults[i].Vendor = netutil.MACVendor(resultSet.RouterResults[i].MacAddr.String())
		}
		if s.AddHostNames {
			resultSet.RouterResults[i].HostName = netutil.ReverseLookup(ctx, resultSet.RouterResults[i].IPAddr.String())
			bar.Increment()
		}
	}

	slices.SortFunc(resultSet.RouterResults, func(a, b NDPRouter) int {
		return a.IPAddr.Compare(b.IPAddr)
	})
	return nil
}

func (r *NDPRouterScannerResults) Print() {
	r.display()
}

func (r *NDPRouterScannerResults) String() string {
	stringBuilder := strings.Builder{}

	funcMap := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
	}
	tmpl := template.Must(
		template.
			New("ndp_router_scan").
			Funcs(funcMap).
			Parse(NDPRoutersTemplate),
	)

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

	hostResults := make([]NDPRouter, 0, 15)

	startSendChan <- struct{}{}

	receivedFrom := make(map[netip.Addr]struct{}) // to keep track of which IPs we have got replies from
	defer func() {
		s.results.RouterResults = hostResults
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
			ip6packet := ip6layer.(*layers.IPv6)
			srcIP := netip.AddrFrom16([16]byte(ip6packet.SrcIP))

			eth := packet.Layer(layers.LayerTypeEthernet)
			if eth == nil {
				continue
			}
			ethPacket := eth.(*layers.Ethernet)

			_, alreadyReceived := receivedFrom[srcIP]
			if alreadyReceived {
				continue
			}
			s.results.PacketsReceived++

			icmpPacket, ok := icmpLayer.(*layers.ICMPv6RouterAdvertisement)
			if !ok {
				continue
			}
			result := NDPRouter{
				IPAddr:      srcIP,
				MacAddr:     netutil.MAC(ethPacket.SrcMAC),
				Iface:       packet.Iface,
				Managed:     icmpPacket.Flags&0x80 != 0,
				OtherConfig: icmpPacket.Flags&0x40 != 0,
			}

			for _, icmpOption := range icmpPacket.Options {
				switch icmpOption.Type {
				case layers.ICMPv6OptSourceAddress:
					result.MacAddr = netutil.MAC(icmpOption.Data)
				case layers.ICMPv6OptPrefixInfo:
					prefixInfo, err := parseIPv6PrefixInfo(icmpOption.Data)
					if err == nil {
						result.PrefixInfo = append(result.PrefixInfo, prefixInfo)
					}
				}
			}

			hostResults = append(hostResults, result)
			receivedFrom[srcIP] = struct{}{}
		}
	}
}

func (r NDPRouterScannerResults) display() {
	if len(r.RouterResults) == 0 {
		fmt.Println()
		pterm.Info.Println("No IPv6 routers found")
	}

	for i, router := range r.RouterResults {
		fmt.Println()
		tableData := pterm.TableData{
			{fmt.Sprintf("Router %d", i+1)},
			{"IP Address", router.IPAddr.String()},
			{"MAC Address", router.MacAddr.String()},
			{"Interface", router.Iface},
		}
		if r.printVendors {
			vendor := cmp.Or(router.Vendor, "(unknown)")
			tableData = append(tableData, []string{"Vendor", vendor})
		}
		if r.printHostNames {
			hostName := cmp.Or(router.HostName, "(unknown)")
			tableData = append(tableData, []string{"Hostname", hostName})
		}

		tableData = append(tableData, []string{"Managed (M)", fmt.Sprintf("%v", router.Managed)})
		tableData = append(tableData, []string{"Other Config (O)", fmt.Sprintf("%v", router.OtherConfig)})
		tableData = append(tableData, []string{"Advertised Prefixes", strconv.Itoa(len(router.PrefixInfo))})

		if len(router.PrefixInfo) > 0 {
			for j, prefix := range router.PrefixInfo {
				tableData = append(
					tableData,
					[]string{""},
					[]string{pterm.FgLightCyan.Sprintf("Prefix %v", j+1)},
					[]string{"Prefix", prefix.Prefix.String()},
					[]string{"On Link", fmt.Sprintf("%v", prefix.OnLink)},
					[]string{"SLAAC Enabled", fmt.Sprintf("%v", prefix.SLAACEnabled)},
					[]string{"Valid Lifetime", fmt.Sprintf("%v", prefix.ValidLifetime.String())},
					[]string{"Preferred Lifetime", fmt.Sprintf("%v", prefix.PreferredLifetime.String())},
				)
			}
		}

		pterm.DefaultTable.
			WithHasHeader().
			WithHeaderStyle(pterm.NewStyle(pterm.Bold, pterm.FgBlue)).
			WithHeaderRowSeparator("-").
			WithBoxed().
			WithData(tableData).
			Render()
	}

	fmt.Println("\nScan Duration:     ", r.ScanDuration.Truncate(time.Millisecond))
	fmt.Println("Packets Sent:      ", r.PacketsSent)
	fmt.Println("Packets Received:  ", r.PacketsReceived)
	fmt.Println("Routers Found:       ", len(r.RouterResults))
}

func parseIPv6PrefixInfo(b []byte) (p IPv6PrefixInformation, err error) {
	if len(b) < 30 {
		return p, fmt.Errorf("ipv6 prefix info is not enough")
	}
	prefixLen := int(b[0])
	flags := b[1]

	p.ValidLifetime = durationFromBytes(b[2:6])
	p.PreferredLifetime = durationFromBytes(b[6:10])
	p.OnLink = flags&0x80 != 0
	p.SLAACEnabled = flags&0x40 != 0

	addrBytes := b[14:30]
	addr, ok := netip.AddrFromSlice(addrBytes)
	if !ok {
		addr = netip.IPv6Unspecified()
	}

	p.Prefix = netip.PrefixFrom(addr, prefixLen)

	return p, nil
}
