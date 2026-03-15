// Package scan is used to get various network information about hosts on a network.
package scan

import (
	"context"
	"fmt"
	"net/netip"

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
	var hostNames map[netip.Addr]string

	numWorkers := cmd.Int("workers")
	if numWorkers > 500 {
		return fmt.Errorf("number of workers cannot go above 500")
	}

	if targetStr := cmd.String("target"); targetStr != "" {
		targets, hostNames, err = scanner.TargetsFromStringWithDNSLookup(targetStr)
		if err != nil {
			return err
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("no hosts to scan provided")
	}
	if portStr := cmd.String("ports"); portStr != "" {
		ports, err = scanner.PortsFromString(portStr)
		if err != nil {
			return err
		}
	}
	if len(ports) == 0 {
		return fmt.Errorf("no ports to scan provided")
	}

	lookUpHostNames := cmd.Bool("hostnames")
	responseTimeout := cmd.Duration("timeout")
	if cmd.Bool("udp") {
		scannerObj := scanner.NewUDPScanner(&scanner.UDPScanOptions{
			Targets:     targets,
			TargetPorts: ports,
		}).WithWorkers(numWorkers).WithHostNames(hostNames, lookUpHostNames).WithTimeout(responseTimeout)

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
		}).WithWorkers(numWorkers).WithHostNames(hostNames, lookUpHostNames).WithTimeout(responseTimeout)
		err := tcpFullScanner.Scan()
		if err != nil {
			return err
		}
		PrintTCPFullScanResults(tcpFullScanner.(*scanner.TCPFullScanner))
	}
	return nil
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
