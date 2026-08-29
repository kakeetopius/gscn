package scanner

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/pterm/pterm"
)

func getResultSet(targets []netip.Prefix, ports []PortNumber, hostnames map[netip.Addr]string, hoststates PingScanResultsMap, protocol string) HostResults {
	results := make(HostResults, len(targets))
	for _, target := range targets {
		netAddr := target.Masked()

		var addr netip.Addr
		if target.IsSingleIP() {
			addr = netAddr.Addr() // if it is a /32 or /128 for IPv6, then dont skip the network address.
		} else {
			addr = netAddr.Addr().Next() // skip the network address.
		}

		for netAddr.Contains(addr) {
			hostResult := HostResult{
				Addr:        addr,
				Ports:       make([]Port, 0, len(ports)),
				portIndex:   make(map[PortNumber]int, len(ports)),
				HostState:   HostStateDown,
				ClosedPorts: len(ports), // all ports start out closed. Scanners must adjust accordingly as results come in
			}
			if hostnames != nil {
				hostResult.HostName = hostnames[addr]
			}
			if hoststates != nil {
				hostResult.HostState = hoststates[addr].HostState
				hostResult.AverageRTT = hoststates[addr].AverageRTT
			}

			for i, p := range ports {
				port := Port{
					Number:   PortNumber(p),
					Protocol: protocol,
					State:    PortStateClosed,
				}
				switch protocol {
				case "tcp":
					port.Name = netutil.TCPServiceName(uint16(p))
				case "udp":
					port.Name = netutil.UDPServiceName(uint16(p))
				}
				hostResult.Ports = append(hostResult.Ports, port)

				hostResult.portIndex[p] = i
			}

			results[addr] = hostResult

			addr = addr.Next()
		}
	}

	return results
}

func pingHosts(ctx context.Context, targets []netip.Prefix, pingTimeout time.Duration, workers int, pingCount int) (PingScanResultsMap, error) {
	pinger := NewPingScanner(PingScanOptions{
		Targets:       targets,
		PingTimeout:   pingTimeout,
		Workers:       workers,
		PingCount:     pingCount,
		ResultMapOnly: true,
	})

	_, err := pinger.Scan(ctx)
	if err != nil {
		return PingScanResultsMap{}, err
	}

	return pinger.ResultMap(), nil
}

func randomEphemeralPort() uint16 {
	var (
		minEphemeralPort = 49152
		maxEphemeralPort = 65535
	)
	return uint16(rand.IntN(maxEphemeralPort-minEphemeralPort+1) + minEphemeralPort)
}

func zeroMac() netutil.MAC {
	return netutil.MAC{0, 0, 0, 0, 0, 0}
}

func joinIfaceNames(ifaces []netutil.Interface) string {
	sb := strings.Builder{}
	switch len(ifaces) {
	case 0:
		return ""
	case 1:
		return ifaces[0].Name
	}

	sb.WriteString(ifaces[0].Name)
	for _, iface := range ifaces[1:] {
		sb.WriteString(", ")
		sb.WriteString(iface.Name)
	}

	return sb.String()
}

func printScanResultsMap(results map[netip.Addr]HostResult, scanTime time.Duration, printUpOnly bool, printOpenOnly bool) {
	var tableData [][]string
	totalHosts := len(results)
	totalUp := 0

	for host, hostResults := range results {
		if hostResults.HostState == HostStateDown && printUpOnly {
			continue
		}

		tableData = pterm.TableData{{"Port", "State", "Service"}}
		name := ""
		if hostResults.HostName != "" {
			name = fmt.Sprintf("(%v)", hostResults.HostName)
		}
		if hostResults.HostState == HostStateDown && totalHosts > 10 {
			continue // do not print hosts that are down if total hosts are above 10
		}
		if hostResults.HostState == HostStateUp {
			totalUp++
		}
		fmt.Printf("\nScan Report for %v %v\n", host, name)

		totalPortsScanned := hostResults.TotalNumberOfPorts()
		for _, port := range hostResults.Ports {
			if port.State == PortStateClosed && printOpenOnly {
				continue
			}
			if port.State == PortStateClosed && totalPortsScanned > 10 {
				continue // do not add closed ports to table if scanned ports are above 10
			}
			tableData = append(tableData, []string{fmt.Sprintf("%v/%v", port.Protocol, port.Number), port.State.String(), port.Name})
		}

		hostStateStyle := pterm.FgDefault
		switch hostResults.HostState {
		case HostStateUp:
			hostStateStyle = pterm.FgGreen
		case HostStateDown:
			hostStateStyle = pterm.FgRed
		}
		fmt.Printf("Host State: %s\n", hostStateStyle.Sprint(hostResults.HostState))
		fmt.Println("Average RTT: ", hostResults.AverageRTT.Truncate(time.Microsecond))
		if len(tableData) > 1 && hostResults.HostState == HostStateUp {
			pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(tableData).Render()
		}
		fmt.Println("Ports Scanned: ", totalPortsScanned)
		fmt.Println("Open Ports:    ", hostResults.OpenPorts)
		fmt.Println("Closed Ports:  ", hostResults.ClosedPorts)
		if hostResults.FilteredPorts > 0 {
			fmt.Println("Filtered Ports: ", hostResults.FilteredPorts)
		}
	}
	fmt.Println("\n──────────────────────────────────────────────")
	fmt.Println("Scan Duration:      ", scanTime.Truncate(time.Millisecond))
	fmt.Printf("Total Hosts Scanned: %v\n", totalHosts)
	fmt.Printf("Hosts that are Up:   %v\n", totalUp)
	fmt.Printf("Hosts that are down: %v\n\n", totalHosts-totalUp)
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
