package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/endobit/oui"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kakeetopius/gscn/internal/bits"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/pterm/pterm"
	"golang.org/x/sys/unix"
)

type ARPScanOptions struct {
	Targets   []netip.Prefix
	Source    netip.Addr
	Interface IfaceOpts
	generalScanOptions
}

type ARPScanResult struct {
	IPAddr   string
	MacAddr  string
	HostName string
	Vendor   string
}

type ARPScanResults struct {
	ResultSet    []ARPScanResult
	hasHostnames bool
	hasVendors   bool
}

func (r *ARPScanResults) HasHostNames() bool {
	return r.hasHostnames
}

func (r *ARPScanResults) HasVendors() bool {
	return r.hasVendors
}

func (ARPScanResults) ResultType() ScanResultType {
	return ARPScanResultType
}

type socketInfo struct {
	socketFD   int
	socketAddr *unix.SockaddrLinklayer
}

type ARPScanStats struct {
	PacketsSent     int
	PacketsReceived int
}
type ARPScanner struct {
	opts             *ARPScanOptions
	results          ARPScanResults
	stats            ARPScanStats
	doReverseLookups bool
	addVendors       bool
}

func NewARPScanner(opts *ARPScanOptions) *ARPScanner {
	return &ARPScanner{
		opts:             opts,
		results:          ARPScanResults{},
		stats:            ARPScanStats{},
		doReverseLookups: false,
		addVendors:       false,
	}
}

func (s *ARPScanner) WithTimeout(timeout time.Duration) *ARPScanner {
	s.opts.Timeout = timeout
	return s
}

func (s *ARPScanner) WithReverseLookups() *ARPScanner {
	s.doReverseLookups = true
	return s
}

func (s *ARPScanner) WithVendors() *ARPScanner {
	s.addVendors = true
	return s
}

func (s *ARPScanner) Scan() error {
	if s.opts == nil {
		return fmt.Errorf("no arp scan options set yet")
	}
	results, err := runArp(s)
	if err != nil {
		return err
	}
	s.results = results
	return nil
}

func (s *ARPScanner) Results() ScanResults {
	resultSet := s.results.ResultSet
	if s.doReverseLookups {
		s.results.hasHostnames = true
		fmt.Println()
		pterm.Info.Println("Trying to resolve hostnames")
		numHosts := len(resultSet)
		bar, err := pterm.DefaultProgressbar.WithTotal(numHosts).Start()
		if err != nil {
			fmt.Println(err)
			return nil
		}

		for i := range resultSet {
			resultSet[i].HostName = ReverseLookup(resultSet[i].IPAddr, s.opts.Timeout)
			bar.Increment()
		}
		bar.Stop()
	}
	if s.addVendors {
		s.results.hasVendors = true
		for i := range resultSet {
			resultSet[i].Vendor = MACVendor(resultSet[i].MacAddr)
		}
	}
	return s.results
}

func (s *ARPScanner) Stats() ScanStats {
	return s.stats
}

func runArp(scanner *ARPScanner) (ARPScanResults, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := scanner.opts

	sockfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, bits.Htons(unix.ETH_P_ARP))
	if err != nil {
		return ARPScanResults{}, err
	}
	addr := &unix.SockaddrLinklayer{
		Ifindex:  opts.Interface.Index,
		Protocol: uint16(bits.Htons(unix.ETH_P_ARP)),
	}
	socketinfo := socketInfo{
		socketFD:   sockfd,
		socketAddr: addr,
	}

	resultsChan := make(chan []ARPScanResult)
	startSending := make(chan struct{})

	go getARPReplies(ctx, scanner, resultsChan, startSending)
	_, ok := <-startSending // wait for packet receiving go routine to finish setup.
	if !ok {
		return ARPScanResults{}, fmt.Errorf("could not capture packets on the interface")
	}

	pterm.Info.Println("Probing host(s) on interface: " + opts.Interface.Name)
	numHosts := util.HostsInIP4Network(opts.Targets)
	bar, err := pterm.DefaultProgressbar.WithTotal(int(numHosts)).Start()
	if err != nil {
		return ARPScanResults{}, err
	}

	for _, target := range opts.Targets {
		IPaddr := target.Masked().Addr() // first IP in range
		for target.Contains(IPaddr) {
			if IPaddr == opts.Source { // skip interfaces' own ip
				bar.Increment()
				IPaddr = IPaddr.Next()
				continue
			} else {
				err = sendArpPacket(&opts.Interface, &opts.Source, &IPaddr, &socketinfo)
				if err != nil {
					return ARPScanResults{}, err
				}
				bar.Increment()
				IPaddr = IPaddr.Next()
			}
		}
	}
	bar.Stop()

	util.WaitTimeout(opts.Timeout, "response")
	cancel() // tell packet receiving routine to stop
	results := <-resultsChan

	return ARPScanResults{ResultSet: results}, nil
}

func sendArpPacket(iface *IfaceOpts, srcIP *netip.Addr, dstIP *netip.Addr, sockinfo *socketInfo) error {
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

	err = unix.Sendto(sockinfo.socketFD, packetBytes, 0, sockinfo.socketAddr)
	if err != nil {
		return err
	}
	return nil
}

func getARPReplies(ctx context.Context, scanner *ARPScanner, resultsChan chan<- []ARPScanResult, startSendChan chan<- struct{}) {
	opts := scanner.opts
	handle, err := pcap.OpenLive(opts.Interface.Name, 1600, false, time.Millisecond)
	if err != nil {
		return
	}
	defer handle.Close()
	err = handle.SetBPFFilter("arp")
	if err != nil {
		fmt.Println("Error setting up packet capturing interface: ", err)
		close(startSendChan)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	results := make([]ARPScanResult, 0, 15)
	receivedFrom := make(map[netip.Addr]struct{}) // to keep track of which IPs we have got replies from

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
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arpPacket, _ := arpLayer.(*layers.ARP)
				if arpPacket.Operation == layers.ARPReply {
					ipAddr, ok := netip.AddrFromSlice(arpPacket.SourceProtAddress)
					if !ok {
						continue
					}
					if !util.CheckIfAddrIsPartOfNetworks(opts.Targets, &ipAddr) {
						// skip responses outside the specified network
						continue
					}
					if ipAddr == opts.Source {
						// skip responses from the capturing interface to other devices.
						continue
					}
					scanner.stats.PacketsReceived++
					_, alreadyReceived := receivedFrom[ipAddr]
					if alreadyReceived {
						continue
					}
					receivedFrom[ipAddr] = struct{}{}
					results = append(results, ARPScanResult{
						IPAddr:  ipAddr.String(),
						MacAddr: net.HardwareAddr(arpPacket.SourceHwAddress).String(),
					})
				}
			}
		}
	}
}

func ReverseLookup(addr string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Second)
	defer cancel()

	resolver := net.Resolver{}
	resolver.PreferGo = true

	names, err := resolver.LookupAddr(ctx, addr)
	if err == nil && len(names) > 0 {
		return names[0]
	}
	return ""
}

func MACVendor(mac string) string {
	return oui.Vendor(mac)
}
