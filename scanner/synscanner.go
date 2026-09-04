package scanner

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
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
	"github.com/kakeetopius/gscn/internal/resolving"
	"github.com/kakeetopius/gscn/internal/routing"
	"github.com/kakeetopius/gscn/packet"
	"github.com/pterm/pterm"
	"golang.org/x/sync/errgroup"
)

type TCPSynScanner struct {
	TCPSynScanOptions

	results       TCPSynScanResults
	hostStates    PingScanResultsMap
	ifaceProvider netutil.NetInterfaceProvider
	logger        log.Logger
	router        routing.Router
	macResolver   resolving.Resolver
}

type TCPSynScanOptions struct {
	Targets             []netip.Prefix
	TargetPorts         []PortNumber
	Workers             int
	PingCount           int
	ResponseTimeout     time.Duration
	HostNames           map[netip.Addr]string
	AddUnknownHostNames bool
	PingTimeout         time.Duration
	SkipPingScan        bool

	PrintUpOnly   bool
	PrintOpenOnly bool
}

type TCPSynScanResults struct {
	Results HostResults     `json:"results"`
	Stats   TCPSynScanStats `json:"stats"`

	printUpOnly   bool `json:"-"`
	printOpenOnly bool `json:"-"`
}

type TCPSynScanStats struct {
	TotalNumOfHosts int           `json:"total_scanned"`
	ScanTime        time.Duration `json:"scan_duration"`
}

func NewTCPSynScanner(opts TCPSynScanOptions) (*TCPSynScanner, error) {
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
	return &TCPSynScanner{
		TCPSynScanOptions: opts,
		results: TCPSynScanResults{
			Results: make(HostResults),
		},
		ifaceProvider: ifaceProvider,
		logger:        log.NewLogger(true),
		macResolver:   resolving.NewResolver(ifaceProvider),
		router:        router,
	}, nil
}

func (s *TCPSynScanner) Scan(ctx context.Context) (ScanResults, error) {
	startTime := time.Now()
	err := s.runTCPSynScan(ctx)
	if err != nil {
		return nil, err
	}

	s.results.Stats.ScanTime = time.Since(startTime)
	s.results.Stats.TotalNumOfHosts = len(s.results.Results)
	s.results.printOpenOnly = s.PrintOpenOnly
	s.results.printUpOnly = s.PrintUpOnly

	s.processResults()
	return &s.results, nil
}

func (s *TCPSynScanner) processResults() {
	if s.AddUnknownHostNames {
		spinner, _ := pterm.DefaultSpinner.Start("Resolving Host Names....")
		defer spinner.Success("Resolving done")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		for host, results := range s.results.Results {
			if results.HostName != "" {
				continue
			}
			name := netutil.ReverseLookup(ctx, host.String())
			results.HostName = name
			s.results.Results[host] = results
		}
	}
}

func (r *TCPSynScanResults) Print() {
	printScanResultsMap(r.Results, r.Stats.ScanTime, r.printUpOnly, r.printOpenOnly, false)
}

func (r *TCPSynScanResults) String() string {
	stringBuilder := strings.Builder{}

	hostTmpl := template.Must(template.New("host_result").Parse(HostResultTemplate))
	tmpl := template.Must(hostTmpl.New("tcp_syn_scan").Parse(TCPSynScanResultsTemplate))

	tmpl.Execute(&stringBuilder, r)
	return stringBuilder.String()
}

func (s *TCPSynScanner) runTCPSynScan(ctx context.Context) (err error) {
	if len(s.Targets) == 0 {
		return fmt.Errorf("no hosts to scan provided")
	}
	if len(s.TargetPorts) == 0 {
		s.TargetPorts = CommonPorts
	}
	if s.Workers <= 0 {
		return fmt.Errorf("invalid number of workers")
	}

	if !s.SkipPingScan {
		// pinging for this scanner type is important because kernel will be build able to build the neighbor cache for those hosts that are up which will
		// be useful for the macResolver
		pingResults, pingErr := pingHosts(ctx, s.Targets, s.PingTimeout, int(s.Workers), s.PingCount)
		if pingErr != nil {
			return pingErr
		}
		s.hostStates = pingResults
	}
	s.results.Results = getResultSet(s.Targets, s.TargetPorts, s.HostNames, s.hostStates, "tcp")

	spinner, err := pterm.DefaultSpinner.Start("Scanning hosts")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			spinner.Fail("Scan Failed")
		} else {
			spinner.Success("Scanning Done")
		}
	}()

	allIfaces, err := s.ifaceProvider.Interfaces()
	if err != nil {
		return err
	}

	var packetSender packet.PacketSender
	// localhostPacketSender is necessary coz if packets heading to localhost or any ip on any of the device's interfaces are injected directly at the datalink,
	// they never reache localhost, so they have to be injected at the ip layer. but the ip layer packet injector only works on linux, so for the other OSes there is
	// no solution yet
	var localhostPacketSender packet.PacketSender
	if runtime.GOOS == "linux" {
		packetSender, err = packet.GetPacketSender(ctx, packet.PacketSenderTypeLinkLayer)
		if err != nil {
			return err
		}
		localhostPacketSender, err = packet.GetPacketSender(ctx, packet.PacketSenderTypeIPLayer)
	} else {
		packetSender, err = packet.GetPacketSender(ctx, packet.PacketSenderTypePcap)
		localhostPacketSender = packetSender
	}
	if err != nil {
		return err
	}
	defer packetSender.Close()
	defer localhostPacketSender.Close()

	packetReceiver, err := packet.NewPacketReceiver(ctx, "(ip or ip6) and tcp", 1500, allIfaces...)
	if err != nil {
		return err
	}
	defer packetReceiver.Close()

	masterDone := make(chan struct{})
	go s.getTCPSynScanResults(ctx, packetReceiver, masterDone)

	jobs := make(chan portScanJob, s.Workers)
	g, ctx := errgroup.WithContext(ctx)
	for range s.Workers {
		g.Go(func() error {
			return s.synScanTCPPort(jobs, packetSender, localhostPacketSender)
		})
	}

	sendPortScanningJobs(ctx, jobs, s.Targets, s.TargetPorts, s.HostNames, s.ResponseTimeout)

	close(jobs)
	err = g.Wait() // wait for all to workers to finish
	if err != nil {
		return err
	}

	packetSender.Wait() // wait for the packet sender to send all packets

	<-time.After(s.ResponseTimeout) // wait for the response timeout
	packetReceiver.Close()

	<-masterDone // wait for master to finish processing what is already enqueued by the packet receiver
	close(masterDone)
	return nil
}

func (s *TCPSynScanner) getTCPSynScanResults(ctx context.Context, packetReceiver packet.PacketReceiver, masterDone chan<- struct{}) {
	// To Be Run By Main Worker (aggregator)
	packetChan := packetReceiver.Packets()

	defer func() {
		masterDone <- struct{}{}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packetChan:
			if !ok {
				return
			}
			// Must be TCP.
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				continue
			}
			tcpPacket, ok := tcpLayer.(*layers.TCP)
			if !ok {
				continue
			}

			// must be a syn-ack
			if !tcpPacket.SYN || !tcpPacket.ACK {
				continue
			}

			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}
			eth := ethLayer.(*layers.Ethernet)

			var srcIP netip.Addr

			// Determine IP version from the Ethernet EtherType and extract the source IP.
			switch eth.EthernetType {
			case layers.EthernetTypeIPv4:
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer == nil {
					continue
				}
				ip := ipLayer.(*layers.IPv4)

				addr, ok := netip.AddrFromSlice(ip.SrcIP)
				if !ok {
					continue
				}
				srcIP = addr
			case layers.EthernetTypeIPv6:
				ipLayer := packet.Layer(layers.LayerTypeIPv6)
				if ipLayer == nil {
					continue
				}
				ip := ipLayer.(*layers.IPv6)

				addr, ok := netip.AddrFromSlice(ip.SrcIP)
				if !ok {
					continue
				}
				srcIP = addr
			default:
				continue
			}

			srcPort := uint16(tcpPacket.SrcPort)

			hostResult, found := s.results.Results[srcIP]
			if !found {
				// response not from our scan
				continue
			}
			hostResult.HostState = HostStateUp

			portIndex, found := hostResult.portIndex[PortNumber(srcPort)]
			if !found {
				continue
			}

			port := hostResult.Ports[portIndex]
			if port.State != PortStateOpen {
				port.State = PortStateOpen
				hostResult.OpenPorts++
				hostResult.ClosedPorts--
			}

			hostResult.Ports[portIndex] = port
			s.results.Results[srcIP] = hostResult
		}
	}
}

func (s *TCPSynScanner) synScanTCPPort(jobs chan portScanJob, packetSender packet.PacketSender, localhostPacketSender packet.PacketSender) error {
	// to be run by workers

	packetBufOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	for job := range jobs {
		packetBuf := gopacket.NewSerializeBuffer()

		portNum := job.target.Port()
		addr := job.target.Addr()

		route, err := s.router.Lookup(addr)
		if err != nil {
			return err
		}

		ps := packetSender
		if addr == route.SrcAddr {
			// if the target addr is the address of the interface, meaning we are sending to ourselves, we use the localhostPacketSender
			ps = localhostPacketSender
		}

		packetHeaders := make([]gopacket.SerializableLayer, 0, 3)

		iface := &route.Interface
		if ps.Type() != packet.PacketSenderTypeIPLayer {
			// If the packetSender is of type PacketSenderTypeIPLayer we dont bother with the ethernet header at all

			var dstMac netutil.MAC

			if addr == route.SrcAddr {
				// if the target is the interface's ip we use the looback interface instead
				iface, err = netutil.LoopbackInterface(s.ifaceProvider)
				if err != nil {
					return err
				}
			} else {
				dstMac, err = s.macResolver.Resolve(route.NextHop)
				var macErr resolving.ErrMacNotFound
				if err != nil {
					if !errors.As(err, &macErr) {
						return err
					}
					// if we fail to get mac we just set to the broadcast.
					dstMac = netutil.MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
				}
			}
			srcMac := netutil.MAC(iface.HardwareAddr)
			if dstMac == nil {
				dstMac = zeroMac()
			}
			if srcMac == nil {
				srcMac = zeroMac()
			}

			eth := &layers.Ethernet{
				SrcMAC:       net.HardwareAddr(srcMac),
				DstMAC:       net.HardwareAddr(dstMac),
				EthernetType: layers.EthernetTypeIPv4,
			}
			if addr.Is6() {
				eth.EthernetType = layers.EthernetTypeIPv6
			}

			packetHeaders = append(packetHeaders, eth)
		}

		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(randomEphemeralPort()),
			DstPort: layers.TCPPort(portNum),
			Seq:     rand.Uint32(),
			SYN:     true,
			Window:  65535,
		}

		var ip gopacket.SerializableLayer
		if addr.Is4() {
			ip4 := &layers.IPv4{
				Version:  4,
				IHL:      5,
				TTL:      64,
				Protocol: layers.IPProtocolTCP,
				SrcIP:    route.SrcAddr.AsSlice(),
				DstIP:    addr.AsSlice(),
			}
			tcp.SetNetworkLayerForChecksum(ip4)
			ip = ip4
		} else {
			ip6 := &layers.IPv6{
				Version:    6,
				HopLimit:   64,
				NextHeader: layers.IPProtocolTCP,
				SrcIP:      route.SrcAddr.AsSlice(),
				DstIP:      addr.AsSlice(),
			}
			tcp.SetNetworkLayerForChecksum(ip6)
			ip = ip6
		}

		packetHeaders = append(packetHeaders, ip, tcp)

		err = gopacket.SerializeLayers(packetBuf, packetBufOpts, packetHeaders...)
		if err != nil {
			return err
		}

		packetBytes := packetBuf.Bytes()

		err = ps.SendPacket(packetBytes, iface)
		if err != nil {
			return err
		}

	}

	return nil
}
