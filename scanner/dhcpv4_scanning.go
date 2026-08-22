package scanner

import (
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/log"
	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/kakeetopius/gscn/packet"
	"github.com/pterm/pterm"
)

type DHCPv4Scanner struct {
	DHCPv4ScannerOpts
	ifaceProvider  netutil.NetInterfaceProvider
	packetReceiver *packet.PcapPacketReceiver
	packetSender   packet.PacketSender
	results        DHCPv4ScannerResults
	logger         log.Logger
}

type DHCPv4ScannerOpts struct {
	Interfaces      []netutil.Interface
	ResponseTimeout time.Duration
	WithHostNames   bool
	WithVendorInfo  bool
	Verbose         bool
	Passive         bool
}

type DHCPv4ScannerResults struct {
	Servers []DHCPv4Server  `json:"servers"`
	Stats   DHCPv4ScanStats `json:"stats"`

	printHostNames bool `json:"-"`
	printVendors   bool `json:"-"`
}

type DHCPv4Server struct {
	IP         netip.Addr  `json:"ip"`
	MACAddress netutil.MAC `json:"mac"`
	HostName   string      `json:"hostname"`
	Vendor     string      `json:"vendor"`

	DHCPv4ServerOptions `json:"options"`
}

type DHCPv4ServerOptions struct {
	OfferedIP  netip.Addr    `json:"offered_ip"`
	SubnetMask netip.Addr    `json:"subnet_mask"`
	BroadCast  netip.Addr    `json:"broadcast"`
	Routers    []netip.Addr  `json:"routers"`
	DNSServers []netip.Addr  `json:"dns_servers"`
	DomainName string        `json:"domain_name"`
	LeaseTime  time.Duration `json:"lease_time"`
}

type DHCPv4ScanStats struct {
	PacketsSent     int           `json:"packets_sent"`
	PacketsReceived int           `json:"packets_received"`
	ScanDuration    time.Duration `json:"scan_duration"`
}

func NewDHCPv4ServerScanner(opts DHCPv4ScannerOpts) (*DHCPv4Scanner, error) {
	ifaceProvider, err := netutil.InterfaceProvider()
	if err != nil {
		return nil, err
	}

	return &DHCPv4Scanner{
		DHCPv4ScannerOpts: opts,
		logger:            log.NewLogger(opts.Verbose),
		ifaceProvider:     ifaceProvider,
	}, nil
}

func (s *DHCPv4Scanner) Scan(ctx context.Context) (ScanResults, error) {
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

	packetReceiver, err := packet.NewPacketReceiver(ctx, "udp and (port 68 or port 67)", 32, s.Interfaces...)
	if err != nil {
		return nil, err
	}
	defer packetReceiver.Close()
	s.packetReceiver = packetReceiver

	start := time.Now()
	err = s.runDhcpv4ServerScanning(ctx)
	if err != nil {
		return nil, err
	}
	s.results.Stats.ScanDuration = time.Since(start)

	err = s.addResultInfo()
	if err != nil {
		return nil, err
	}
	return s.results, nil
}

func (r DHCPv4ScannerResults) Print() {
	displayDHCPServerResults(&r, r.printHostNames, r.printVendors)
}

func (r DHCPv4ScannerResults) String() string {
	stringBuilder := strings.Builder{}

	funcMap := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
		"join": joinAddrs,
	}
	tmpl := template.Must(
		template.
			New("dhcpv4_scan").
			Funcs(funcMap).
			Parse(DHCPScanResultsTemplate),
	)

	tmpl.Execute(&stringBuilder, r)
	return stringBuilder.String()
}

func (s *DHCPv4Scanner) addResultInfo() error {
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

func (s *DHCPv4Scanner) runDhcpv4ServerScanning(ctx context.Context) (err error) {
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
	s.logger.WaitTimeout(s.ResponseTimeout, "response")
	s.packetReceiver.Close()

	<-receiverDone // wait for receiving routine to finish
	close(receiverDone)

	return nil
}

func (s *DHCPv4Scanner) scanDhcpServersOnInterface(iface *netutil.Interface) error {
	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    netip.IPv4Unspecified().AsSlice(),
		DstIP:    netip.MustParseAddr("255.255.255.255").AsSlice(),
	}

	udp := &layers.UDP{
		SrcPort: 68,
		DstPort: 67,
	}
	udp.SetNetworkLayerForChecksum(ip4)

	const macAddrLen = 6
	const dhcpFlags uint16 = 0x8000 // 1000...upto 15 0s -> only the first bit is set to tell the server to broadcast the response.
	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  uint8(macAddrLen),
		Xid:          rand.Uint32(),
		ClientHWAddr: iface.HardwareAddr,
		Flags:        dhcpFlags,
		Options: layers.DHCPOptions{
			// dhcp option 53 which specifies dhcp message type ie dhcpdiscover message
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}),
			// dhcp option 61 which is client id (client mac address) and the first byte should be the hardware type
			layers.NewDHCPOption(layers.DHCPOptClientID, append([]byte{byte(layers.LinkTypeEthernet)}, iface.HardwareAddr...)),
			// dhcp option 55 which specifies the paramters we want the server to give us.
			layers.NewDHCPOption(layers.DHCPOptParamsRequest, []byte{
				byte(layers.DHCPOptSubnetMask),
				byte(layers.DHCPOptRouter),
				byte(layers.DHCPOptDNS),
				byte(layers.DHCPOptDomainName),
				byte(layers.DHCPOptBroadcastAddr),
				byte(layers.DHCPOptLeaseTime),
			}),
			layers.NewDHCPOption(layers.DHCPOptEnd, []byte{byte(layers.DHCPMsgTypeDiscover)}),
		},
	}
	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(
		buf,
		opts,
		eth,
		ip4,
		udp,
		dhcp,
	)
	if err != nil {
		return err
	}

	packet := buf.Bytes()
	return s.packetSender.SendPacket(packet, iface)
}

func (s *DHCPv4Scanner) getDHCPScanResults(ctx context.Context, startSendChan chan<- struct{}, receiverDone chan<- struct{}) {
	packetChan := s.packetReceiver.Packets()

	results := make([]DHCPv4Server, 0, 5)
	receivedFrom := make(map[netip.Addr]struct{})

	defer func() {
		s.results.Servers = results
		receiverDone <- struct{}{}
	}()

	startSendChan <- struct{}{}

outer:
	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packetChan:
			if !ok {
				return
			}

			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}
			ipPacket := ipLayer.(*layers.IPv4)
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

			dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
			if dhcpLayer == nil {
				continue
			}
			dhcpPacket := dhcpLayer.(*layers.DHCPv4)

			if dhcpPacket.Operation != layers.DHCPOpReply {
				continue
			}
			s.results.Stats.PacketsReceived++

			dhcpServer := DHCPv4Server{
				MACAddress: netutil.MAC(ethPacket.SrcMAC),
			}
			ip, ok := netip.AddrFromSlice(dhcpPacket.YourClientIP)
			if ok {
				dhcpServer.OfferedIP = ip
			}

			for _, opts := range dhcpPacket.Options {
				switch opts.Type {
				case layers.DHCPOptMessageType:
					msgType := opts.Data[0]
					if msgType != byte(layers.DHCPMsgTypeOffer) {
						continue outer
					}
				case layers.DHCPOptServerID:
					addr, ok := netip.AddrFromSlice(opts.Data)
					if ok {
						dhcpServer.IP = addr
					}
				case layers.DHCPOptSubnetMask:
					addr, ok := netip.AddrFromSlice(opts.Data)
					if ok {
						dhcpServer.SubnetMask = addr
					}
				case layers.DHCPOptBroadcastAddr:
					addr, ok := netip.AddrFromSlice(opts.Data)
					if ok {
						dhcpServer.BroadCast = addr
					}
				case layers.DHCPOptRouter:
					addrs, err := decodeAddrSlice(opts.Data)
					if err == nil {
						dhcpServer.Routers = addrs
					}
				case layers.DHCPOptDNS:
					addrs, err := decodeAddrSlice(opts.Data)
					if err == nil {
						dhcpServer.DNSServers = addrs
					}
				case layers.DHCPOptLeaseTime:
					leaseTime := durationFromSlice(opts.Data)
					dhcpServer.LeaseTime = leaseTime
				case layers.DHCPOptDomainName:
					dhcpServer.DomainName = string(opts.Data)
				}
			}

			results = append(results, dhcpServer)
		}
	}
}

func displayDHCPServerResults(dhcpResults *DHCPv4ScannerResults, withHostNames bool, withVendors bool) {
	if len(dhcpResults.Servers) == 0 {
		fmt.Println()
		pterm.Info.Println("No DHCPv4 Servers found")
	} else {
		for i, result := range dhcpResults.Servers {
			fmt.Println()

			tableData := pterm.TableData{
				{fmt.Sprintf("Server %d", i+1)},
				{"IP Address", result.IP.String()},
				{"MAC Address", result.MACAddress.String()},
			}

			if withVendors {
				vendor := cmp.Or(result.Vendor, "(unknown)")
				tableData = append(tableData, []string{"Vendor", vendor})
			}

			if withHostNames {
				hostName := cmp.Or(result.HostName, "(unknown)")
				tableData = append(tableData, []string{"Hostname", hostName})
			}

			opts := result.DHCPv4ServerOptions

			if opts.OfferedIP.IsValid() {
				tableData = append(tableData, []string{"Offered IP", opts.OfferedIP.String()})
			}
			if opts.SubnetMask.IsValid() {
				tableData = append(tableData, []string{"Subnet Mask", opts.SubnetMask.String()})
			}
			if opts.BroadCast.IsValid() {
				tableData = append(tableData, []string{"BroadCast", opts.BroadCast.String()})
			}
			tableData = append(
				tableData,
				[]string{"Routers", joinAddrs(opts.Routers)},
				[]string{"DNS Servers", joinAddrs(opts.DNSServers)},
				[]string{"Domain Name", cmp.Or(opts.DomainName, "(unknown)")},
				[]string{"Lease Time", opts.LeaseTime.String()},
			)

			pterm.DefaultTable.
				WithHasHeader().
				WithHeaderRowSeparator("-").
				WithBoxed().
				WithData(tableData).
				Render()
		}
	}

	fmt.Println("\nScan Duration:      ", dhcpResults.Stats.ScanDuration.Truncate(time.Millisecond))
	fmt.Println("Packets Sent:       ", dhcpResults.Stats.PacketsSent)
	fmt.Println("Packets Received:   ", dhcpResults.Stats.PacketsReceived)
	fmt.Println("Servers Found:      ", len(dhcpResults.Servers))
}

func joinAddrs(addrs []netip.Addr) string {
	result := make([]string, len(addrs))
	for i, addr := range addrs {
		result[i] = addr.String()
	}

	return strings.Join(result, ", ")
}

func decodeAddrSlice(b []byte) ([]netip.Addr, error) {
	if len(b)%4 != 0 {
		return nil, fmt.Errorf("invalid ip address slice")
	}

	const ip4AddrLen = 4

	numAddrs := len(b) / ip4AddrLen
	addrs := make([]netip.Addr, 0, numAddrs)

	lower := 0
	upper := ip4AddrLen
	for range numAddrs {
		addrSlice := b[lower:upper]

		addr, ok := netip.AddrFromSlice(addrSlice)
		if ok {
			addrs = append(addrs, addr)
		}

		lower = upper
		upper += ip4AddrLen
	}

	return addrs, nil
}

func durationFromSlice(b []byte) time.Duration {
	duration := binary.BigEndian.Uint32(b)
	return time.Duration(duration) * time.Second
}
