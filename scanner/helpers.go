package scanner

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
					port.Name = netutil.Service(layers.TCPPort(p).String())
				case "udp":
					port.Name = netutil.Service(layers.UDPPort(p).String())
				}
				hostResult.Ports = append(hostResult.Ports, port)

				hostResult.portIndex[PortNumber(p)] = i
			}

			results[addr] = hostResult

			addr = addr.Next()
		}
	}

	return results
}

func pingHosts(targets []netip.Prefix, pingTimeout time.Duration, workers int, pingCount int) (PingScanResultsMap, error) {
	pinger := NewPingScanner(PingScanOptions{
		Targets:       targets,
		PingTimeout:   pingTimeout,
		Workers:       workers,
		PingCount:     pingCount,
		ResultMapOnly: true,
	})

	_, err := pinger.Scan()
	if err != nil {
		return PingScanResultsMap{}, err
	}

	return pinger.ResultMap(), nil
}

func zeroMac() MAC {
	return MAC{0, 0, 0, 0, 0, 0}
}

func randomEphemeralPort() uint16 {
	var (
		minEphemeralPort = 49152
		maxEphemeralPort = 65535
	)
	return uint16(rand.IntN(maxEphemeralPort-minEphemeralPort+1) + minEphemeralPort)
}

func resolveMAC(addr netip.Addr, ifaceProvider netutil.NetInterfaceProvider) (MAC, error) {
	allIfaces, err := ifaceProvider.Interfaces()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	filter := fmt.Sprintf("dst host %s", addr.String())

	packetReceiver, err := NewPacketReceiver(ctx, filter, 1, allIfaces...)
	if err != nil {
		return nil, err
	}
	defer packetReceiver.Close()

	packets := packetReceiver.Packets()

	// dial and try to send some data to the destination ip so we can read the dst mac that will be used by the kernel.
	conn, err := net.Dial("udp", fmt.Sprintf("%v:%v", addr.String(), 69))
	if err != nil {
		return nil, err
	}
	conn.Write([]byte("wagwan"))

	var packet gopacket.Packet
	select {
	case <-time.After(1 * time.Second):
		return nil, ErrCouldNotGetMAC
	case p, ok := <-packets:
		if !ok {
			return nil, ErrCouldNotGetMAC
		}
		packet = p
	}

	eth := packet.Layer(layers.LayerTypeEthernet)
	if eth == nil {
		return nil, ErrCouldNotGetMAC
	}
	ethHdr, ok := eth.(*layers.Ethernet)
	if !ok {
		return nil, ErrCouldNotGetMAC
	}

	return MAC(ethHdr.DstMAC), nil
}

func getAllIfaceNames(ifaces []netutil.Interface) string {
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
			service := netutil.Service(layers.TCPPort(port.Number).String())
			tableData = append(tableData, []string{fmt.Sprintf("%v/%v", port.Protocol, port.Number), port.State.String(), service})
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
