package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
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
	Servers []DHCPv4Server        `json:"servers"`
	Stats   DHCPv4ServerScanStats `json:"stats"`

	printHostNames bool `json:"-"`
	printVendors   bool `json:"-"`
}

type DHCPv4Server struct {
	IP         netip.Addr  `json:"ip"`
	MACAddress netutil.MAC `json:"mac"`
	HostName   string      `json:"hostname"`
	Vendor     string      `json:"vendor"`
}

type DHCPv4ServerScanStats struct {
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

	packetReceiver, err := packet.NewPacketReceiver(ctx, "udp and (port 68 or port 67)", 1024, s.Interfaces...)
	if err != nil {
		return nil, err
	}
	defer packetReceiver.Close()
	s.packetReceiver = packetReceiver

	start := time.Now()
	err = s.runDhcpServerScanning(ctx)
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
	return ""
}

func (s *DHCPv4Scanner) addResultInfo() error {
	numServers := len(s.results.Servers)
	s.results.printHostNames = s.WithHostNames
	s.results.printVendors = s.WithVendorInfo

	var bar *pterm.ProgressbarPrinter
	var err error
	if s.WithHostNames {
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

func (s *DHCPv4Scanner) runDhcpServerScanning(ctx context.Context) (err error) {
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

	macAddrLen := 6
	const dhcpBroadcastFlag uint16 = 0x8000
	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  uint8(macAddrLen),
		Xid:          rand.Uint32(),
		ClientHWAddr: iface.HardwareAddr,
		Flags:        dhcpBroadcastFlag,
		Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}),
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

			var ip netip.Addr
			for _, opts := range dhcpPacket.Options {
				if opts.Type == layers.DHCPOptServerID {
					addr, ok := netip.AddrFromSlice(opts.Data)
					if ok {
						ip = addr
					}
				}
			}

			results = append(results, DHCPv4Server{
				IP:         ip,
				MACAddress: netutil.MAC(ethPacket.SrcMAC),
			})
		}
	}
}

func displayDHCPServerResults(dhcpResults *DHCPv4ScannerResults, withHostNames bool, withVendors bool) {
	if len(dhcpResults.Servers) == 0 {
		fmt.Println()
		pterm.Info.Println("No DHCPv4 Servers found")
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

		for _, result := range dhcpResults.Servers {
			row := []string{result.IP.String(), result.MACAddress.String()}
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
		pterm.DefaultTable.WithHasHeader().WithHeaderRowSeparator("-").WithBoxed().WithData(tableData).Render()
	}
	fmt.Println("\nScan Duration:      ", dhcpResults.Stats.ScanDuration.Truncate(time.Millisecond))
	fmt.Println("Packets Sent:       ", dhcpResults.Stats.PacketsSent)
	fmt.Println("Packets Received:   ", dhcpResults.Stats.PacketsReceived)
	fmt.Println("Hosts Found:        ", len(dhcpResults.Servers))
}
