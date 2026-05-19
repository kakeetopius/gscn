package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kakeetopius/gscn/internal/log"
	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/pterm/pterm"
)

type ARPScanner struct {
	*ARPScanOptions
	results ARPScanResults
	stats   ARPScanStats
	logger  log.Logger
}

type ARPScanOptions struct {
	Targets             []netip.Prefix
	Source              netip.Addr
	Interface           util.Interface
	ResponseTimeout     time.Duration
	WithVendorInfo      bool
	HostNames           map[netip.Addr]string
	AddUnknownHostNames bool
	Workers             int
	MessageNotifier     notifier.Notifier
}

type ARPScanResults struct {
	ResultSet    []ARPScanResult
	hasHostnames bool
	hasVendors   bool
}

type ARPScanResult struct {
	IPAddr   netip.Addr
	MacAddr  net.HardwareAddr
	HostName string
	Vendor   string
}

type ARPScanStats struct {
	PacketsSent     int
	PacketsReceived int
	ScanTime        time.Duration
}

func NewARPScanner(opts *ARPScanOptions) *ARPScanner {
	if opts.HostNames == nil {
		opts.HostNames = make(map[netip.Addr]string)
	}
	return &ARPScanner{
		ARPScanOptions: opts,
		results:        ARPScanResults{},
		stats:          ARPScanStats{},
		logger:         log.NewLogger(true),
	}
}

func (s *ARPScanner) Scan() error {
	if s.ARPScanOptions == nil {
		return fmt.Errorf("no arp scan options set yet")
	}
	start := time.Now()
	results, err := runArp(s)
	if err != nil {
		return err
	}
	stop := time.Now()
	s.results = results
	s.stats.ScanTime = stop.Sub(start)
	return nil
}

func (s *ARPScanner) Results() ScanResults {
	resultSet := s.results.ResultSet
	if s.AddUnknownHostNames {
		s.results.hasHostnames = true
		fmt.Println()
		s.logger.Info("Trying to resolve hostnames")
		numHosts := len(resultSet)
		bar, err := pterm.DefaultProgressbar.WithTotal(numHosts).Start()
		if err != nil {
			fmt.Println(err)
			return nil
		}

		for i := range resultSet {
			resultSet[i].HostName = ReverseLookup(resultSet[i].IPAddr.String(), s.ResponseTimeout)
			bar.Increment()
		}
		bar.Stop()
	}
	if s.WithVendorInfo {
		s.results.hasVendors = true
		for i := range resultSet {
			resultSet[i].Vendor = util.MACVendor(resultSet[i].MacAddr.String())
		}
	}

	slices.SortFunc(resultSet, func(a, b ARPScanResult) int {
		return a.IPAddr.Compare(b.IPAddr)
	})

	s.results.ResultSet = resultSet
	return s.results
}

func (s *ARPScanner) SendResultsViaNotifier() error {
	if s.MessageNotifier == nil {
		return fmt.Errorf("arpscanner: no notifier is set")
	}
	spinner, err := pterm.DefaultSpinner.Start("Sending Results....")
	if err != nil {
		spinner.Fail()
		return err
	}

	err = s.MessageNotifier.SendMessage(s.results.String())
	if err != nil {
		spinner.Fail()
		return err
	}

	spinner.Success("Results Sent")
	return nil
}

func (s *ARPScanner) Stats() ScanStats {
	return s.stats
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

func (r ARPScanResults) String() string {
	stringBuilder := strings.Builder{}
	fmt.Fprintln(&stringBuilder, "ARP Scan Results")

	for _, result := range r.ResultSet {
		fmt.Fprintf(&stringBuilder, "IP: %v\nMac: %v\nVendor: %v\nHostName: %v\n\n", result.IPAddr, result.MacAddr, result.Vendor, result.HostName)
	}

	return stringBuilder.String()
}

func runArp(scanner *ARPScanner) (ARPScanResults, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := scanner.ARPScanOptions

	resultsChan := make(chan []ARPScanResult)
	startSending := make(chan struct{})
	errorChan := make(chan error)

	go getARPReplies(ctx, scanner, resultsChan, startSending, errorChan)

outer:
	for {
		select {
		case err := <-errorChan:
			return ARPScanResults{}, err
		case <-startSending:
			break outer
		}
	}

	scanner.logger.Info("Probing host(s) on interface: " + opts.Interface.Name)
	numHosts := util.HostsInIP4Network(opts.Targets)
	bar, err := pterm.DefaultProgressbar.WithTotal(int(numHosts)).Start()
	if err != nil {
		return ARPScanResults{}, err
	}
	defer bar.Stop()

	for _, target := range opts.Targets {
		IPaddr := target.Masked().Addr() // first IP in range
		networkAddr := IPaddr
		broadCast := broadCastAddr(target)
		for target.Contains(IPaddr) {
			if (IPaddr == networkAddr || IPaddr == broadCast) && !target.IsSingleIP() {
				IPaddr = IPaddr.Next()
				continue
			}

			err = sendArpPacket(&opts.Interface, &opts.Source, &IPaddr)
			if err != nil {
				return ARPScanResults{}, err
			}
			scanner.stats.PacketsSent++
			bar.Increment()
			IPaddr = IPaddr.Next()
		}
	}

	scanner.logger.WaitTimeout(opts.ResponseTimeout, "response")
	cancel() // tell packet receiving routine to stop
	results := <-resultsChan

	return ARPScanResults{ResultSet: results}, nil
}

func sendArpPacket(iface *util.Interface, srcIP *netip.Addr, dstIP *netip.Addr) error {
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

	err = sendPacket(packetBytes, iface)
	if err != nil {
		return err
	}
	return nil
}

func getARPReplies(ctx context.Context, scanner *ARPScanner, resultsChan chan<- []ARPScanResult, startSendChan chan<- struct{}, errorChan chan<- error) {
	opts := scanner.ARPScanOptions
	handle, err := pcap.OpenLive(opts.Interface.PcapName, 1600, false, time.Millisecond)
	if err != nil {
		errorChan <- err
		return
	}

	defer handle.Close()
	err = handle.SetBPFFilter("arp")
	if err != nil {
		errorChan <- err
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
			if !util.AddrIsPartOfNetworks(opts.Targets, &ipAddr) {
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
				IPAddr:  ipAddr,
				MacAddr: net.HardwareAddr(arpPacket.SourceHwAddress),
			})
		}
	}
}

func ReverseLookup(addr string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resolver := net.Resolver{}
	resolver.PreferGo = true

	names, err := resolver.LookupAddr(ctx, addr)
	if err == nil && len(names) > 0 {
		return names[0]
	}
	return ""
}

func broadCastAddr(networkPrefix netip.Prefix) netip.Addr {
	networkAddr := networkPrefix.Masked().Addr()
	hostBitLen := 32 - networkPrefix.Bits()

	ip := networkAddr.As4()

	ipUint := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	mask := uint32((1 << hostBitLen) - 1)

	broadCast := ipUint | mask

	return netip.AddrFrom4([4]byte{byte(broadCast >> 24), byte(broadCast >> 16), byte(broadCast >> 8), byte(broadCast)})
}
