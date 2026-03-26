package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kakeetopius/gscn/internal/bits"
	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/pterm/pterm"
	"golang.org/x/sys/unix"
)

type NDPScanOptions struct {
	Targets   []netip.Prefix
	Source    netip.Addr
	Interface Interface
	logger    io.Writer
	timeout   time.Duration
}

type NDPScanResult struct {
	IPAddr   string
	MacAddr  string
	HostName string
	Vendor   string
}

type NDPScanStats struct {
	PacketsSent     int
	PacketsReceived int
}

type NDPScanResults struct {
	ResultSet    []NDPScanResult
	hasHostNames bool
	hasVendors   bool
}

func (NDPScanResults) ResultType() ScanResultType {
	return NDPScanResultType
}

func (r NDPScanResults) String() string {
	stringBuilder := strings.Builder{}
	fmt.Fprintln(&stringBuilder, "ARP Scan Results")

	for _, result := range r.ResultSet {
		fmt.Fprintf(&stringBuilder, "IP: %v\nMac: %v\nVendor: %v\nHostName: %v\n\n", result.IPAddr, result.MacAddr, result.Vendor, result.HostName)
	}

	return stringBuilder.String()
}

func (r NDPScanResults) HasHostNames() bool {
	return r.hasHostNames
}

func (r NDPScanResults) HasVendors() bool {
	return r.hasVendors
}

type NDPScanner struct {
	opts             *NDPScanOptions
	results          NDPScanResults
	stats            NDPScanStats
	doReverseLookups bool
	addVendors       bool
}

func NewNDPScanner(opts *NDPScanOptions) Scanner {
	return &NDPScanner{
		opts:             opts,
		results:          NDPScanResults{},
		stats:            NDPScanStats{},
		addVendors:       false,
		doReverseLookups: false,
	}
}

func (s *NDPScanner) WithWorkers(w int) Scanner {
	return s
}

func (s *NDPScanner) WithTimeout(timeout time.Duration) Scanner {
	s.opts.timeout = timeout
	return s
}

func (s *NDPScanner) WithHostNames(_ map[netip.Addr]string, _ bool) Scanner {
	s.doReverseLookups = true
	return s
}

func (s *NDPScanner) WithVendorInfo() Scanner {
	s.addVendors = true
	return s
}

func (s *NDPScanner) WithNotifier(notifier.Notifier) Scanner {
	return s
}

func (s *NDPScanner) Scan() error {
	if s.opts == nil {
		return fmt.Errorf("no ndp options set yet")
	}
	results, err := runIPv6Disc(s)
	if err != nil {
		return err
	}
	s.results = results
	return nil
}

func (s *NDPScanner) Results() ScanResults {
	resultSet := s.results.ResultSet
	if s.doReverseLookups {
		s.results.hasHostNames = true
		fmt.Println()
		pterm.Info.Println("Trying to resolve hostnames")
		numHosts := len(resultSet)
		bar, err := pterm.DefaultProgressbar.WithTotal(numHosts).Start()
		if err != nil {
			fmt.Println(err)
			return nil
		}

		for i := range resultSet {
			resultSet[i].HostName = ReverseLookup(resultSet[i].IPAddr, s.opts.timeout)
			bar.Increment()
		}
		bar.Stop()
	}
	if s.addVendors {
		s.results.hasVendors = true
		for i := range resultSet {
			resultSet[i].Vendor = util.MACVendor(resultSet[i].MacAddr)
		}
	}
	return s.results
}

func (s *NDPScanner) Stats() ScanStats {
	return s.stats
}

func runIPv6Disc(scanner *NDPScanner) (NDPScanResults, error) {
	opts := scanner.opts
	resultChan := make(chan NDPScanResults)
	startSendChan := make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go getNeighbourAdvertisements(ctx, scanner, resultChan, startSendChan)

	_, ok := <-startSendChan // wait for packet receving routine to set up
	if !ok {
		return NDPScanResults{}, fmt.Errorf("error capturing packets on that interface")
	}
	spinner, err := pterm.DefaultSpinner.Start("Probing host on interface: " + opts.Interface.Name)
	if err != nil {
		return NDPScanResults{}, err
	}

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
	spinner.Stop()

	util.WaitTimeout(opts.timeout, "response")
	cancel() // tell packet receiving routine to stop
	results := <-resultChan
	return results, nil
}

func sendNSPacket(scanner *NDPScanner, dstIP *netip.Addr) error {
	sockfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, bits.Htons(unix.ETH_P_ARP))
	if err != nil {
		return err
	}
	iface := scanner.opts.Interface
	addr := &unix.SockaddrLinklayer{
		Ifindex:  iface.Index,
		Protocol: uint16(bits.Htons(unix.ETH_P_ARP)),
	}

	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       solicitedNodeMacAddress(*dstIP),
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip := &layers.IPv6{
		SrcIP:      scanner.opts.Source.AsSlice(),
		DstIP:      solicitedNodeIPAddress(*dstIP),
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
	}

	icmp := &layers.ICMPv6{
		TypeCode: layers.ICMPv6TypeNeighborSolicitation << 8,
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
	err = gopacket.SerializeLayers(buf, options, eth, ip, icmp, nd)
	if err != nil {
		fmt.Println(err)
		return err
	}

	packetBytes := buf.Bytes()

	err = unix.Sendto(sockfd, packetBytes, 0, addr)
	if err != nil {
		return err
	}
	scanner.stats.PacketsSent++
	return nil
}

func getNeighbourAdvertisements(ctx context.Context, scanner *NDPScanner, resultsChan chan<- NDPScanResults, startSendChan chan<- struct{}) {
	iface := scanner.opts.Interface
	handle, err := pcap.OpenLive(iface.Name, 1600, false, time.Millisecond)
	if err != nil {
		return
	}
	defer handle.Close()
	err = handle.SetBPFFilter("icmp6 and icmp6[0] == 136") // 136 is the number for ICMPv6TypeNeighborSolicitation
	if err != nil {
		fmt.Println("Error setting up packet capturing interface: ", err)
		close(startSendChan)
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
			if icmpLayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement); icmpLayer != nil {
				ip6layer := packet.Layer(layers.LayerTypeIPv6)
				ip6packet, ok := ip6layer.(*layers.IPv6)
				if !ok {
					continue
				}
				srcIP := netip.AddrFrom16([16]byte(ip6packet.SrcIP))
				if !util.AddrIsPartOfNetworks(scanner.opts.Targets, &srcIP) {
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
				result.IPAddr = srcIP.String()
				result.MacAddr = hwAddr.String()
				if icmpPacket.Router() {
					result.MacAddr = fmt.Sprintf("%v (router)", hwAddr)
				}
				results.ResultSet = append(results.ResultSet, result)
			}
		}
	}
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
