// Package scan is used to get various network information about hosts on a network.
package scan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/kakeetopius/gscn/pkg/scanner"
	"github.com/pterm/pterm"
	"github.com/urfave/cli/v3"
)

func RunScan(clictx context.Context, cmd *cli.Command) error {
	var err error
	targets := make([]netip.Prefix, 0)
	ports := make([]uint, 0)

	numWorkers := cmd.Int("workers")
	if numWorkers > 500 {
		return fmt.Errorf("number of workers cannot go above 500")
	}

	if targetStr := cmd.String("target"); targetStr != "" {
		targets, err = scanTargetsFromString(targetStr)
		if err != nil {
			return err
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("no hosts to scan provided")
	}
	if portStr := cmd.String("ports"); portStr != "" {
		ports, err = util.PortsFromString(portStr)
		if err != nil {
			return err
		}
	}
	if len(ports) == 0 {
		return fmt.Errorf("no ports to scan provided")
	}

	if cmd.Bool("udp") {
		scannerObj := scanner.NewUDPScanner(&scanner.UDPScanOptions{
			Targets:     targets,
			TargetPorts: ports,
		})

		udpScanner := scannerObj.(*scanner.UDPScanner)
		err := udpScanner.Scan()
		if err != nil {
			return err
		}
		PrintUDPScanResults(udpScanner)
	} else {
		tcpFullScanner := scanner.NewTCPFullScanner(&scanner.TCPFullScanOptions{
			Targets:     targets,
			TargetPorts: ports,
		}).WithWorkers(numWorkers)
		err := tcpFullScanner.Scan()
		if err != nil {
			return err
		}
		PrintTCPFullScanResults(tcpFullScanner.(*scanner.TCPFullScanner))
	}
	return nil
}

func scanTargetsFromString(s string) ([]netip.Prefix, error) {
	// Example: 10.1.1.1/24,10.1.1.1,bing.com,10.1.1.1-2,google.com
	commaSeparatedTargets := strings.Split(s, ",")
	targets := make([]netip.Prefix, 0, 5)

	// For dns lookup incase ip address parsing fails.
	resolver := net.Resolver{}

	for _, targetString := range commaSeparatedTargets {
		var err error
		if strings.ContainsRune(targetString, '/') {
			// CIDR Notation Provided eg 10.1.1.1/24
			var network netip.Prefix
			network, err = netip.ParsePrefix(targetString)
			if err == nil {
				targets = append(targets, network)
			}
		} else if strings.ContainsRune(targetString, '-') {
			// IP Range provided eg 10.1.1.1-10
			var IPsInRange []netip.Prefix
			IPsInRange, err = util.ParseIPRange(targetString)
			targets = append(targets, IPsInRange...)
		} else {
			// Single IP Presumed eg 10.1.1.1
			var addr netip.Addr
			addr, err = netip.ParseAddr(targetString)
			bitlen := 32
			if addr.Is6() {
				bitlen = 128
			}
			if err == nil {
				targets = append(targets, netip.PrefixFrom(addr, bitlen))
			}
		}
		if err != nil {
			// if some errors occured while Parsing assume it is domain name
			IPs, resolverr := resolver.LookupIP(context.Background(), "ip4", strings.Trim(targetString, " "))
			if resolverr != nil {
				return nil, resolverr
			}
			addr, ok := netip.AddrFromSlice(IPs[0])
			if !ok {
				return nil, fmt.Errorf("could not resolve: %v", targetString)
			}
			// HostNames[addr] = targetString
			targets = append(targets, netip.PrefixFrom(addr, 32))
		}
	}

	return util.Unique(targets), nil
}

func PrintTCPFullScanResults(tcpFullScanner *scanner.TCPFullScanner) {
	var tcpFullScanResults scanner.TCPFullScanResults
	if results, ok := tcpFullScanner.Results().(scanner.TCPFullScanResults); ok {
		tcpFullScanResults = results
	} else {
		return
	}

	var tableData [][]string
	for host, hostResults := range tcpFullScanResults.ResultMap {
		tableData = pterm.TableData{{"Port", "State", "Service"}}
		name := ""
		if hostResults.HostName != "" {
			name = fmt.Sprintf("(%v)", hostResults.HostName)
		}
		fmt.Printf("\nScan Report for %v %v\n", host, name)
		for _, port := range hostResults.Ports {
			if port.State == scanner.PortStateClosed {
				continue // no need to add closed port to table
			}
			tcpService := util.ServiceFromGoPacketString(layers.TCPPort(port.Number).String())
			tableData = append(tableData, []string{fmt.Sprintf("%v/%v", port.Protocol, port.Number), port.State.String(), tcpService})
		}
		if hostResults.OpenPorts > 0 {
			pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(tableData).Render()
		}
		fmt.Println("Ports Scanned: ", hostResults.OpenPorts+hostResults.ClosedPorts)
		fmt.Println("Open Ports: ", hostResults.OpenPorts)
		fmt.Println("Closed Ports: ", hostResults.ClosedPorts)
	}
}

func PrintUDPScanResults(udpScanner *scanner.UDPScanner) {
	var tcpFullScanResults scanner.UDPScanResults
	if results, ok := udpScanner.Results().(scanner.UDPScanResults); ok {
		tcpFullScanResults = results
	} else {
		return
	}

	var tableData [][]string
	for host, hostResults := range tcpFullScanResults.ResultMap {
		tableData = pterm.TableData{{"Port", "State", "Service"}}
		name := ""
		if hostResults.HostName != "" {
			name = fmt.Sprintf("(%v)", hostResults.HostName)
		}
		fmt.Printf("\nScan Report for %v %v\n", host, name)
		for _, port := range hostResults.Ports {
			if port.State == scanner.PortStateClosed {
				continue // no need to add closed port to table
			}
			tcpService := util.ServiceFromGoPacketString(layers.TCPPort(port.Number).String())
			tableData = append(tableData, []string{fmt.Sprintf("%v/%v", port.Protocol, port.Number), port.State.String(), tcpService})
		}
		if hostResults.OpenPorts > 0 {
			pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(tableData).Render()
		}
		fmt.Println("Ports Scanned: ", hostResults.OpenPorts+hostResults.ClosedPorts)
		fmt.Println("Open Ports: ", hostResults.OpenPorts)
		fmt.Println("Closed Ports: ", hostResults.ClosedPorts)
	}
}
