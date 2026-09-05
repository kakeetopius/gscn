package scanner

import (
	"cmp"
	"context"
	"fmt"
	"html/template"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/log"
	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/kakeetopius/gscn/packet"
	"github.com/pterm/pterm"
)

type CDPScanner struct {
	CDPScannerOptions
	results        CDPScanResults
	packetReceiver packet.PacketReceiver
	ifaceProvider  netutil.NetInterfaceProvider
	logger         log.Logger
}

type CDPScannerOptions struct {
	Interfaces  []netutil.Interface
	WaitTimeout time.Duration
	Verbose     bool
}

type CDPScanResults struct {
	Hosts        []CDPHost `json:"hosts"`
	CDPScanStats `json:"stats"`
}

type CDPHost struct {
	MAC             netutil.MAC     `json:"mac_address"`
	CDPVersion      byte            `json:"cdp_version"`
	DeviceID        string          `json:"device_id"`
	Addresses       []netip.Addr    `json:"addresses"`
	PortID          string          `json:"port_id"`
	Platform        string          `json:"platform"`
	SoftwareVersion string          `json:"software_version"`
	IPPrefixes      []netip.Prefix  `json:"ip_prefixes"`
	VTPDomain       string          `json:"vtp_domain"`
	NativeVLAN      uint16          `json:"native_vlan"`
	FullDuplex      bool            `json:"full_duplex"`
	MTU             uint32          `json:"mtu"`
	SysName         string          `json:"system_name"`
	SysOID          string          `json:"system_oid"`
	ManagementIPs   []netip.Addr    `json:"management_ips"`
	Capabilites     CDPCapabilities `json:"capabilites"`
}

type CDPCapabilities struct {
	L3Router        bool `json:"is_l3_router"`
	TBBridge        bool `json:"is_transparent_bridge"`
	SPBridge        bool `json:"is_source_route_bridge"`
	L2Switch        bool `json:"is_l2_switch"`
	IsHost          bool `json:"is_host"`
	IGMPFilter      bool `json:"supports_igmp_filtering"`
	L1Repeater      bool `json:"is_l1_repeater"`
	IsPhone         bool `json:"is_phone"`
	RemotelyManaged bool `json:"is_remotely_managed"`
}

type CDPScanStats struct {
	PacketsReceived int           `json:"packets_received"`
	ScanDuration    time.Duration `json:"scan_duration"`
	NumHosts        int           `json:"number_of_hosts"`
}

func (c CDPCapabilities) String() string {
	var capabilities []string

	if c.L3Router {
		capabilities = append(capabilities, "L3 Router")
	}
	if c.TBBridge {
		capabilities = append(capabilities, "Transparent Bridge")
	}
	if c.SPBridge {
		capabilities = append(capabilities, "Source-Route Bridge")
	}
	if c.L2Switch {
		capabilities = append(capabilities, "L2 Switch")
	}
	if c.IsHost {
		capabilities = append(capabilities, "Host")
	}
	if c.IGMPFilter {
		capabilities = append(capabilities, "IGMP Filter")
	}
	if c.L1Repeater {
		capabilities = append(capabilities, "L1 Repeater")
	}
	if c.IsPhone {
		capabilities = append(capabilities, "Phone")
	}
	if c.RemotelyManaged {
		capabilities = append(capabilities, "Remotely Managed")
	}

	if len(capabilities) == 0 {
		return "None"
	}

	return strings.Join(capabilities, ", ")
}

func NewCDPScanner(opts CDPScannerOptions) (*CDPScanner, error) {
	ifaceProvider, err := netutil.InterfaceProvider()
	if err != nil {
		return nil, err
	}
	return &CDPScanner{
		CDPScannerOptions: opts,
		ifaceProvider:     ifaceProvider,
		logger:            log.NewLogger(opts.Verbose),
	}, nil
}

func (s *CDPScanner) Scan(ctx context.Context) (ScanResults, error) {
	packetReceiver, err := packet.NewPacketReceiver(ctx, "ether dst 01:00:0c:cc:cc:cc", 64, s.Interfaces...)
	if err != nil {
		return nil, err
	}
	defer packetReceiver.Close()
	s.packetReceiver = packetReceiver

	start := time.Now()
	err = s.scanForCDPHosts(ctx)
	if err != nil {
		return nil, err
	}
	s.results.ScanDuration = time.Since(start)
	s.results.NumHosts = len(s.results.Hosts)

	return s.results, nil
}

func (r CDPScanResults) Print() {
	r.display()
}

func (r CDPScanResults) String() string {
	stringBuilder := strings.Builder{}

	funcMap := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
		"joinAddrs":    joinAddrs,
		"joinPrefixes": joinPrefixes,
	}
	tmpl := template.Must(
		template.
			New("cdp_scan").
			Funcs(funcMap).
			Parse(CDPHostsTemplate),
	)

	tmpl.Execute(&stringBuilder, r)
	return stringBuilder.String()
}

func (s *CDPScanner) scanForCDPHosts(ctx context.Context) (err error) {
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

	if len(s.Interfaces) == 0 {
		return fmt.Errorf("no network interfaces provided")
	}

	receiverDone := make(chan struct{})
	go s.getCDPPackets(ctx, receiverDone)

	s.logger.Info("Scanning for CDP neighbours on interface(s): " + joinIfaceNames(s.Interfaces))
	for _, iface := range s.Interfaces {
		s.packetReceiver.AddInterface(iface)
	}

	s.logger.WaitTimeout(ctx, s.WaitTimeout, "")

	s.packetReceiver.Close()
	<-receiverDone

	return nil
}

func (s *CDPScanner) getCDPPackets(ctx context.Context, receiverDone chan<- struct{}) {
	packetChan := s.packetReceiver.Packets()

	hosts := make([]CDPHost, 0, 5)
	receivedFrom := make(map[[6]byte]struct{}) // key is mac address as a 6byte array.

	defer func() {
		s.results.Hosts = hosts
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
			host := CDPHost{}

			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}
			ethPacket := ethLayer.(*layers.Ethernet)

			host.MAC = netutil.MAC(ethPacket.SrcMAC)
			if _, found := receivedFrom[host.MAC.To6()]; found {
				continue
			}
			receivedFrom[host.MAC.To6()] = struct{}{}

			cdpLayer := packet.Layer(layers.LayerTypeCiscoDiscovery)
			if cdpLayer == nil {
				continue
			}
			cdpPacket := cdpLayer.(*layers.CiscoDiscovery)
			s.results.PacketsReceived++

			host.CDPVersion = cdpPacket.Version

			cdpInfoLayer := packet.Layer(layers.LayerTypeCiscoDiscoveryInfo)
			if cdpInfoLayer == nil {
				continue
			}
			cdpInfo := cdpInfoLayer.(*layers.CiscoDiscoveryInfo)

			host.DeviceID = cdpInfo.DeviceID
			host.Addresses = netutil.IPSliceToAddrSlice(cdpInfo.Addresses)
			host.PortID = cdpInfo.PortID
			host.Platform = cdpInfo.Platform
			host.SoftwareVersion = cdpInfo.Version
			ipPrefixes, err := netutil.IPNetSliceToPrefixSlice(cdpInfo.IPPrefixes)
			if err == nil {
				host.IPPrefixes = ipPrefixes
			}
			host.VTPDomain = cdpInfo.VTPDomain
			host.NativeVLAN = cdpInfo.NativeVLAN
			host.FullDuplex = cdpInfo.FullDuplex
			host.MTU = cdpInfo.MTU
			host.SysName = cdpInfo.SysName
			host.SysOID = cdpInfo.SysOID
			host.ManagementIPs = netutil.IPSliceToAddrSlice(cdpInfo.MgmtAddresses)
			host.Capabilites = CDPCapabilities(cdpInfo.Capabilities)

			hosts = append(hosts, host)
		}
	}
}

func (r CDPScanResults) display() {
	for i, host := range r.Hosts {
		defaultStr := "(unknown)"
		nativeVlan := defaultStr
		if host.NativeVLAN != 0 {
			nativeVlan = strconv.Itoa(int(host.NativeVLAN))
		}
		mtu := defaultStr
		if host.MTU != 0 {
			mtu = strconv.FormatUint(uint64(host.MTU), 10)
		}
		data := pterm.TableData{
			{fmt.Sprintf("Device %d", i+1)},
			{"MAC Address", host.MAC.String()},
			{"CDP Version", strconv.Itoa(int(host.CDPVersion))},
			{"Device ID", cmp.Or(host.DeviceID, defaultStr)},
			{"Addresses", joinAddrs(host.Addresses)},
			{"Port ID", cmp.Or(host.PortID, defaultStr)},
			{"Platform", cmp.Or(host.Platform, defaultStr)},
			{"Software Version", cmp.Or(wrapString(host.SoftwareVersion, 50), defaultStr)},
			{"IP Prefixes", joinPrefixes(host.IPPrefixes)},
			{"VTP Domain", cmp.Or(host.VTPDomain, defaultStr)},
			{"Native VLAN", nativeVlan},
			{"Full Duplex", strconv.FormatBool(host.FullDuplex)},
			{"MTU", mtu},
			{"System Name", cmp.Or(host.SysName, defaultStr)},
			{"System OID", cmp.Or(host.SysOID, defaultStr)},
			{"Management IPs", joinAddrs(host.ManagementIPs)},
			{"Capabilities", cmp.Or(host.Capabilites.String(), "None")},
		}

		pterm.DefaultTable.
			WithHasHeader().
			WithHeaderRowSeparator("-").
			WithBoxed(true).
			WithData(data).
			Render()
	}

	fmt.Println("\nScan Duration:      ", r.ScanDuration.Truncate(time.Millisecond))
	fmt.Println("Packets Received:   ", r.PacketsReceived)
	fmt.Println("Hosts Found:      ", r.NumHosts)
}
