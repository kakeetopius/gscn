package scanner

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/log"
	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/kakeetopius/gscn/internal/route"
	"github.com/pterm/pterm"
)

type TCPSynScanner struct {
	TCPSynScanOptions

	results       TCPSynScanResults
	hostStates    PingScanResultsMap
	ifaceProvider netutil.NetInterfaceProvider
	logger        log.Logger
	router        route.Router

	resolveCache map[netip.Addr]MAC
	cacheMu      sync.RWMutex
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

func NewTCPSynScanner(opts TCPSynScanOptions) *TCPSynScanner {
	if opts.HostNames == nil {
		opts.HostNames = make(map[netip.Addr]string)
	}
	return &TCPSynScanner{
		TCPSynScanOptions: opts,
		results: TCPSynScanResults{
			Results: make(HostResults),
		},
		logger:        log.NewLogger(true),
		resolveCache:  make(map[netip.Addr]MAC),
		ifaceProvider: &netutil.RealNetInterfaceProvider{},
	}
}

func (s *TCPSynScanner) Scan() (ScanResults, error) {
	router, err := route.NewRouter()
	if err != nil {
		return nil, err
	}
	s.router = router

	startTime := time.Now()
	err = s.runTCPSynScan()
	if err != nil {
		return nil, err
	}
	stopTime := time.Now()

	s.results.Stats.ScanTime = stopTime.Sub(startTime)
	s.results.Stats.TotalNumOfHosts = len(s.results.Results)
	s.results.printOpenOnly = s.PrintOpenOnly
	s.results.printUpOnly = s.PrintUpOnly

	s.addResultsInfo()
	return &s.results, nil
}

func (s *TCPSynScanner) addResultsInfo() {
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
	printScanResultsMap(r.Results, r.Stats.ScanTime, r.printUpOnly, r.printOpenOnly)
}

func (r *TCPSynScanResults) String() string {
	stringBuilder := strings.Builder{}

	hostTmpl := template.Must(template.New("host_result").Parse(HostResultTemplate))
	tmpl := template.Must(hostTmpl.New("tcp_full_scan").Parse(TCPSynScanResultsTemplate))

	tmpl.Execute(&stringBuilder, r)
	return stringBuilder.String()
}

func (s *TCPSynScanner) runTCPSynScan() error {
	if len(s.Targets) == 0 {
		return fmt.Errorf("no hosts to scan provided")
	}
	if len(s.TargetPorts) == 0 {
		s.TargetPorts = CommonPorts
	}

	if !s.SkipPingScan {
		pingResults, err := pingHosts(s.Targets, s.PingTimeout, int(s.Workers), s.PingCount) // first check if hosts are up.
		if err != nil {
			return err
		}
		s.hostStates = pingResults
	}
	s.results.Results = getResultSet(s.Targets, s.TargetPorts, s.HostNames, s.hostStates, "tcp")

	spinner, err := pterm.DefaultSpinner.Start("Scanning hosts")
	if err != nil {
		return err
	}
	defer spinner.Success("Scanning Done")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	allIfaces, err := s.ifaceProvider.Interfaces()
	if err != nil {
		return err
	}

	var packetSender PacketSender
	// localhostPacketSender is necessary coz if packets heading to localhost or any ip on any of the device's interfaces are injected directly at the datalink,
	// they never reache localhost, so they have to be injected at the ip layer. but the ip layer packet injector only works on linux, so for the other OSes there is
	// no solution yet
	var localhostPacketSender PacketSender
	if runtime.GOOS == "linux" {
		packetSender, err = GetPacketSender(ctx, PacketSenderTypeLinkLayer)
		if err != nil {
			return err
		}
		localhostPacketSender, err = GetPacketSender(ctx, PacketSenderTypeIPLayer)
	} else {
		packetSender, err = GetPacketSender(ctx, PacketSenderTypePcap)
		localhostPacketSender = packetSender
	}
	if err != nil {
		return err
	}
	defer packetSender.Close()

	defer localhostPacketSender.Close()

	receiverCtx, cancelReceiver := context.WithCancel(context.Background())
	defer cancelReceiver()
	packetReceiver, err := NewPacketReceiver(receiverCtx, "(ip or ip6) and tcp", 1500, allIfaces...)
	if err != nil {
		return err
	}
	defer packetReceiver.Close()

	masterDone := make(chan struct{})

	go s.getTCPSynScanResults(ctx, packetReceiver, masterDone)

	jobs := make(chan PortScanJob, s.Workers)
	wg := &sync.WaitGroup{}
	for range s.Workers {
		wg.Add(1)
		go s.synScanTCPPort(wg, jobs, packetSender, localhostPacketSender)
	}

	senderDone := make(chan struct{})
	go sendPortScanningJobs(ctx, senderDone, jobs, s.Targets, s.TargetPorts, s.ResponseTimeout)

	<-senderDone // wait for sender to send all jobs
	close(senderDone)

	close(jobs)
	wg.Wait() // wait for all to workers to finish

	packetSender.Wait() // wait for the packet sender to send all packets

	<-time.After(s.ResponseTimeout) // wait for the response timeout
	packetReceiver.Close()

	<-masterDone // wait for master to finish processing what is already enqueued by the packet receiver
	close(masterDone)

	return nil
}

func (s *TCPSynScanner) getTCPSynScanResults(ctx context.Context, packetReceiver PacketReceiver, masterDone chan<- struct{}) {
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
			hostResult.OpenPorts++
			hostResult.ClosedPorts--
			hostResult.HostState = HostStateUp

			portIndex := hostResult.portIndex[PortNumber(srcPort)]

			port := hostResult.Ports[portIndex]
			port.State = PortStateOpen

			hostResult.Ports[portIndex] = port
			s.results.Results[srcIP] = hostResult
		}
	}
}

func (s *TCPSynScanner) synScanTCPPort(wg *sync.WaitGroup, jobs chan PortScanJob, packetSender PacketSender, localhostPacketSender PacketSender) {
	// to be run by workers
	defer func() {
		wg.Done()
	}()

	for job := range jobs {
		portNum := job.target.Port()
		addr := job.target.Addr()

		route, err := s.router.Lookup(addr)
		if err != nil {
			continue
		}

		if addr == route.SrcAddr {
			// if the target addr is the address of the interface, meaning we are sending to ourselves, we use the localhostPacketSender
			packetSender = localhostPacketSender
		}

		packetHeaders := make([]gopacket.SerializableLayer, 0, 3)

		iface := &route.Interface
		if packetSender.Type() != PacketSenderTypeIPLayer {
			// If the packetSender is of type PacketSenderTypeIPLayer we dont bother with the ethernet header at all

			var dstMac MAC

			if addr == route.SrcAddr {
				// if the target is the interface's ip we use the looback interface instead
				iface, err = netutil.LoobackInterface(s.ifaceProvider)
				if err != nil {
					continue
				}
			} else {
				dstMac, err = s.getMACOf(route.NextHop)
				if err != nil {
					if !errors.Is(err, ErrCouldNotGetMAC) {
						continue
					}
					// if we fail to get mac we just set to the broadcast.
					dstMac = MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
				}
			}
			srcMac := MAC(iface.HardwareAddr)
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
			SrcPort:    layers.TCPPort(randomEphemeralPort()),
			DstPort:    layers.TCPPort(portNum),
			Seq:        rand.Uint32(),
			SYN:        true,
			Window:     1024,
			DataOffset: 5,
			Options: []layers.TCPOption{
				{
					OptionType:   layers.TCPOptionKindMSS,
					OptionLength: 4,
					OptionData:   []byte{0x05, 0xb4}, // 1460
				},
			},
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

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		err = gopacket.SerializeLayers(buf, opts, packetHeaders...)
		if err != nil {
			fmt.Println(err)
			continue
		}

		packetBytes := buf.Bytes()

		err = packetSender.SendPacket(packetBytes, iface)
		if err != nil {
			fmt.Println(err)
			continue
		}

	}
}

func (s *TCPSynScanner) getMACOf(addr netip.Addr) (MAC, error) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	if mac, found := s.resolveCache[addr]; found {
		return mac, nil
	}

	var err error
	var mac MAC

	if addr.IsLoopback() {
		mac = MAC{0, 0, 0, 0, 0, 0}
	} else {
		mac, err = resolveMAC(addr, s.ifaceProvider)
		if err != nil {
			return nil, err
		}
	}

	s.resolveCache[addr] = mac
	return mac, nil
}
