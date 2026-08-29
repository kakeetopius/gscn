package scanner

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
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

type DHCPv6Scanner struct {
	DHCPv6ScannerOpts
	ifaceProvider  netutil.NetInterfaceProvider
	packetReceiver *packet.PcapPacketReceiver
	packetSender   packet.PacketSender
	results        DHCPv6ScannerResults
	logger         log.Logger
}

type DHCPv6ScannerOpts struct {
	Interfaces      []netutil.Interface
	ResponseTimeout time.Duration
	WithHostNames   bool
	WithVendorInfo  bool
	Verbose         bool
	Passive         bool
}

type DHCPv6ScannerResults struct {
	Servers []DHCPv6Server  `json:"servers"`
	Stats   DHCPv6ScanStats `json:"stats"`

	printHostNames bool `json:"-"`
	printVendors   bool `json:"-"`
}

type DHCPv6Server struct {
	IP         netip.Addr  `json:"ip"`
	MACAddress netutil.MAC `json:"mac"`
	HostName   string      `json:"hostname"`
	Vendor     string      `json:"vendor"`
	Iface      string      `json:"iface"`

	DHCPv6ServerOptions `json:"options"`
}

type DHCPv6ServerOptions struct {
	IANA                DHCPv6IANA   `json:"ia_na"`
	DNSRecursiveServers []netip.Addr `json:"dns_servers"`
	DomainSearchList    []string     `json:"domain_names"`
}

type DHCPv6ScanStats struct {
	PacketsSent     int           `json:"packets_sent"`
	PacketsReceived int           `json:"packets_received"`
	ScanDuration    time.Duration `json:"scan_duration"`
}

type DHCPv6IANA struct {
	Address           netip.Addr    `json:"addr"`
	RenewalTime       time.Duration `json:"renewal_time"`
	RebindTime        time.Duration `json:"rebind_time"`
	PreferredLifetime time.Duration `json:"preferred_lifetime"`
	ValidLifetime     time.Duration `json:"valid_lifetime"`
}

func NewDHCPv6ServerScanner(opts DHCPv6ScannerOpts) (*DHCPv6Scanner, error) {
	ifaceProvider, err := netutil.InterfaceProvider()
	if err != nil {
		return nil, err
	}

	return &DHCPv6Scanner{
		DHCPv6ScannerOpts: opts,
		logger:            log.NewLogger(opts.Verbose),
		ifaceProvider:     ifaceProvider,
	}, nil
}

func (s *DHCPv6Scanner) Scan(ctx context.Context) (ScanResults, error) {
	var err error
	var packetSender packet.PacketSender
	if runtime.GOOS == "linux" {
		packetSender, err = packet.GetPacketSender(ctx, packet.PacketSenderTypeLinkLayer)
	} else {
		packetSender, err = packet.GetPacketSender(ctx, packet.PacketSenderTypePcap)
	}
	if err != nil {
		return nil, err
	}

	defer packetSender.Close()
	s.packetSender = packetSender

	packetReceiver, err := packet.NewPacketReceiver(ctx, "udp and (port 546 or port 547)", 32, s.Interfaces...)
	if err != nil {
		return nil, err
	}
	defer packetReceiver.Close()
	s.packetReceiver = packetReceiver

	start := time.Now()
	err = s.runDhcpv6ServerScanning(ctx)
	if err != nil {
		return nil, err
	}
	s.results.Stats.ScanDuration = time.Since(start)

	err = s.processResults()
	if err != nil {
		return nil, err
	}
	return s.results, nil
}

func (r DHCPv6ScannerResults) Print() {
	r.display()
}

func (r DHCPv6ScannerResults) String() string {
	stringBuilder := strings.Builder{}

	funcMap := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
		"joinAddrs": joinAddrs,
		"join": func(s []string) string {
			return strings.Join(s, ", ")
		},
	}
	tmpl := template.Must(
		template.
			New("dhcpv6_scan").
			Funcs(funcMap).
			Parse(DHCPv6ScanResultsTemplate),
	)

	tmpl.Execute(&stringBuilder, r)
	return stringBuilder.String()
}

func (s *DHCPv6Scanner) processResults() error {
	numServers := len(s.results.Servers)
	s.results.printHostNames = s.WithHostNames
	s.results.printVendors = s.WithVendorInfo

	var bar *pterm.ProgressbarPrinter
	var err error
	if s.WithHostNames && numServers > 0 {
		fmt.Println()
		s.logger.Info("Trying to resolve hostnames")
		bar, err = pterm.DefaultProgressbar.WithTotal(numServers).Start()
		if err != nil {
			return err
		}
		defer bar.Stop()
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.ResponseTimeout)
	defer cancel()
	for i := range s.results.Servers {
		if s.WithVendorInfo {
			s.results.Servers[i].Vendor = netutil.MACVendor(s.results.Servers[i].MACAddress.String())
		}
		if s.WithHostNames {
			s.results.Servers[i].HostName = netutil.ReverseLookup(ctx, s.results.Servers[i].IP.String())
			bar.Increment()
		}
	}

	return nil
}

func (s *DHCPv6Scanner) runDhcpv6ServerScanning(ctx context.Context) (err error) {
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
	receiverDone := make(chan struct{})
	go s.getDHCPScanResults(ctx, startSending, receiverDone)
	<-startSending // wait for receiving routine to finish setup

	if !s.Passive {
		for _, iface := range s.Interfaces {
			s.packetReceiver.AddReceivingInterface(iface)
			err := s.scanDhcpServersOnInterface(&iface)
			if err != nil {
				return err
			}
			s.results.Stats.PacketsSent++
		}
		s.packetSender.Wait()
	}
	s.logger.Info("Scanning for dhcpv6 on interface(s): " + joinIfaceNames(s.Interfaces))
	s.logger.WaitTimeout(s.ResponseTimeout, "response")
	s.packetReceiver.Close()

	<-receiverDone // wait for receiving routine to finish
	close(receiverDone)

	return nil
}

func (s *DHCPv6Scanner) scanDhcpServersOnInterface(iface *netutil.Interface) error {
	srcIP, err := iface.LinkLocalAddress()
	if err != nil {
		if errors.Is(err, netutil.ErrNoLinkLocalAddrress) {
			srcIP = netip.IPv6Unspecified()
		} else {
			return err
		}
	}
	dstIP := netip.MustParseAddr("ff02::1:2") // all dhcp servers and relay agents multicast address

	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       solicitedNodeMacAddress(dstIP),
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      srcIP.AsSlice(),
		DstIP:      dstIP.AsSlice(),
	}

	udp := &layers.UDP{
		SrcPort: 546,
		DstPort: 547,
	}
	udp.SetNetworkLayerForChecksum(ip6)

	dhcpv6 := &layers.DHCPv6{
		MsgType:       layers.DHCPv6MsgTypeSolicit,
		TransactionID: getTransactionID(),
		Options: layers.DHCPv6Options{
			// duid is the the DHCP Unique ID which is required to by the dhcpv6 server to uniquely identify the client
			layers.NewDHCPv6Option(layers.DHCPv6OptClientID, getDUID(iface.HardwareAddr)),
			// iana - identity association for non temporary address
			// it is required such that the dhcpv6 server can give us a normal (non-temporary) ipv6 addres...whatever that means.
			// Without it no Advertise message is returned
			layers.NewDHCPv6Option(layers.DHCPv6OptIANA, getIANA()),
		},
	}

	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(
		buf,
		opts,
		eth,
		ip6,
		udp,
		dhcpv6,
	)
	if err != nil {
		return err
	}

	packet := buf.Bytes()
	return s.packetSender.SendPacket(packet, iface)
}

func (s *DHCPv6Scanner) getDHCPScanResults(ctx context.Context, startSendChan chan<- struct{}, receiverDone chan<- struct{}) {
	packetChan := s.packetReceiver.Packets()

	results := make([]DHCPv6Server, 0, 5)
	receivedFrom := make(map[netip.Addr]struct{})

	defer func() {
		s.results.Servers = results
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

			ipLayer := packet.Layer(layers.LayerTypeIPv6)
			if ipLayer == nil {
				continue
			}
			ipPacket := ipLayer.(*layers.IPv6)
			addr, ok := netip.AddrFromSlice(ipPacket.SrcIP)
			if !ok {
				continue
			}

			if _, alreadyRecieved := receivedFrom[addr]; alreadyRecieved {
				continue
			}
			receivedFrom[addr] = struct{}{}

			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}
			ethPacket := ethLayer.(*layers.Ethernet)

			dhcpLayer := packet.Layer(layers.LayerTypeDHCPv6)
			if dhcpLayer == nil {
				continue
			}
			dhcpPacket := dhcpLayer.(*layers.DHCPv6)

			if dhcpPacket.MsgType != layers.DHCPv6MsgTypeAdvertise {
				continue
			}
			s.results.Stats.PacketsReceived++

			dhcpServer := DHCPv6Server{
				MACAddress: netutil.MAC(ethPacket.SrcMAC),
				Iface:      packet.Iface,
				IP:         addr,
			}

			for _, opt := range dhcpPacket.Options {
				switch opt.Code {
				case layers.DHCPv6OptIANA:
					// contains the offered IP and other stuff like lifetime duration, renewal time, etc
					iana, err := decodeIANA(opt.Data)
					if err == nil {
						dhcpServer.IANA = iana
					}
				case layers.DHCPv6OptDNSServers:
					// contains dns server ip addresses
					addrs, err := decodeIPSliceFromBytes(opt.Data, ip6AddrLen)
					if err == nil {
						dhcpServer.DNSRecursiveServers = addrs
					}
				case layers.DHCPv6OptDomainList:
					// contains list of domain names
					dhcpServer.DomainSearchList = domainNamesFromBytes(opt.Data)
				case layers.DHCPv6OptServerID:
					// this is the MAC of the DHCPv6 Server
					duid := layers.DHCPv6DUID{}
					err := duid.DecodeFromBytes(opt.Data)
					if err == nil {
						dhcpServer.MACAddress = netutil.MAC(duid.LinkLayerAddress)
					}
				}
			}

			results = append(results, dhcpServer)
		}
	}
}

func (r DHCPv6ScannerResults) display() {
	if len(r.Servers) == 0 {
		fmt.Println()
		pterm.Info.Println("No DHCPv6 Servers found")
	}

	for i, server := range r.Servers {
		fmt.Println()

		tableData := pterm.TableData{
			{fmt.Sprintf("Server %d", i+1)},
			{"IP Address", server.IP.String()},
			{"MAC Address", server.MACAddress.String()},
			{"Interface", server.Iface},
		}

		if r.printVendors {
			vendor := cmp.Or(server.Vendor, "(unknown)")
			tableData = append(tableData, []string{"Vendor", vendor})
		}

		if r.printHostNames {
			hostName := cmp.Or(server.HostName, "(unknown)")
			tableData = append(tableData, []string{"Hostname", hostName})
		}

		if len(server.DNSRecursiveServers) != 0 {
			tableData = append(tableData, []string{"DNS Recursive Server(s)", joinAddrs(server.DNSRecursiveServers)})
		}
		if len(server.DomainSearchList) != 0 {
			tableData = append(tableData, []string{"Domain Search List", strings.Join(server.DomainSearchList, ", ")})
		}

		if server.IANA.Address.IsValid() {
			tableData = append(tableData, []string{"Offered IP", server.IANA.Address.String()})
		}
		tableData = append(
			tableData,
			[]string{"Preferred Lifetime", server.IANA.PreferredLifetime.String()},
			[]string{"Valid Lifetime", server.IANA.ValidLifetime.String()},
			[]string{"Renewal Time", server.IANA.RenewalTime.String()},
			[]string{"Rebind Time", server.IANA.RebindTime.String()},
		)

		pterm.DefaultTable.
			WithHasHeader().
			WithHeaderRowSeparator("-").
			WithBoxed().
			WithData(tableData).
			Render()
	}
	fmt.Println("\nScan Duration:      ", r.Stats.ScanDuration.Truncate(time.Millisecond))
	fmt.Println("Packets Sent:       ", r.Stats.PacketsSent)
	fmt.Println("Packets Received:   ", r.Stats.PacketsReceived)
	fmt.Println("Servers Found:      ", len(r.Servers))
}

func getTransactionID() []byte {
	transactionID := make([]byte, 3)
	rand.Read(transactionID)
	return transactionID
}

func getIANA() []byte {
	iana := make([]byte, 12)
	rand.Read(iana[:4]) // read in random IAID (identity association id)
	return iana
}

func decodeIANA(b []byte) (i DHCPv6IANA, err error) {
	if len(b) < 12 {
		return i, fmt.Errorf("invalid IA_NA data")
	}
	options := make(layers.DHCPv6Options, 5)

	i.RenewalTime = durationFromBytes(b[4:8]) // T1
	i.RebindTime = durationFromBytes(b[8:12]) // T2

	offset := 12 // 12 bytes from the start of the option skips the IAID and the 2 timers T1 and T2 each being 4 bytes
	stop := len(b)

	// first decode the nested dhcpv6 options within the IA_NA option
	for offset < stop {
		opt, err := decodeDhcp6Opt(b[offset:])
		if err != nil {
			return DHCPv6IANA{}, err
		}
		options = append(options, opt)
		offset += int(opt.Length) + 4 // 2 from option code, 2 from option length
	}

	// look for the nested option called IAADDR and populate the IANA struct
	for _, opt := range options {
		if opt.Code == layers.DHCPv6OptIAAddr {
			if len(opt.Data) < 24 { // minimum length for IAADDR
				continue
			}
			ip, ok := netip.AddrFromSlice(opt.Data[:16])
			if !ok {
				continue
			}
			i.Address = ip

			i.PreferredLifetime = durationFromBytes(opt.Data[16:20])
			i.ValidLifetime = durationFromBytes(opt.Data[20:24])
		}
	}

	return i, nil
}

func decodeDhcp6Opt(data []byte) (o layers.DHCPv6Option, err error) {
	if len(data) < 4 {
		return o, errors.New("not enough data to decode")
	}
	o.Code = layers.DHCPv6Opt(binary.BigEndian.Uint16(data[0:2]))
	o.Length = binary.BigEndian.Uint16(data[2:4])
	if len(data) < 4+int(o.Length) {
		return o, fmt.Errorf("dhcpv6 option size < length %d", 4+o.Length)
	}
	o.Data = data[4 : 4+o.Length]

	return o, nil
}

func getDUID(mac net.HardwareAddr) []byte {
	ethernetHWType := make([]byte, 2)
	binary.BigEndian.PutUint16(ethernetHWType, uint16(layers.LinkTypeEthernet))
	duid := layers.DHCPv6DUID{
		Type:             layers.DHCPv6DUIDTypeLL,
		LinkLayerAddress: mac,
		HardwareType:     ethernetHWType,
	}
	return duid.Encode()
}
