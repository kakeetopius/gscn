// Package scan is used to get various network information about hosts on a network.
package scan

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/notifier"
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
	if len(ports) == 0 && !cmd.Bool("ping") {
		return fmt.Errorf("no ports to scan provided")
	}

	lookUpHostNames := cmd.Bool("hostnames")
	waitTimeout := cmd.Duration("timeout")

	notify := cmd.Bool("notify")
	var notifiyObj notifier.Notifier
	if notify {
		config, err := util.NewConfig()
		if err != nil {
			return err
		}
		notifierName := config.GetString("notifier.type")
		if notifierName == "" {
			return fmt.Errorf("no notifier type set in the config file")
		}
		notifiyObj, err = notifier.NotifierByName(notifierName, config)
		if err != nil {
			return err
		}
	}
	if cmd.Bool("udp") {
		udpScanner := scanner.NewUDPScanner(scanner.UDPScanOptions{
			Targets:             targets,
			TargetPorts:         ports,
			Workers:             uint(numWorkers),
			HostNames:           hostNames,
			AddUnknownHostNames: lookUpHostNames,
			ResponseTimeout:     waitTimeout,
			PingTimeout:         cmd.Duration("ping-timeout"),
		})
		if notify {
			udpScanner.MessageNotifier = notifiyObj
		}
		err := udpScanner.Scan()
		if err != nil {
			return err
		}
		PrintUDPScanResults(udpScanner)
		if notify {
			err := udpScanner.SendResultsViaNotifier()
			if err != nil {
				return err
			}
		}

	} else if cmd.Bool("ping") {
		pingScanner := scanner.NewPingScanner(scanner.PingScanOptions{
			Targets:             targets,
			PingTimeout:         cmd.Duration("ping-timeout"),
			AddUnknownHostNames: lookUpHostNames,
			HostNames:           hostNames,
		})
		if notify {
			pingScanner.MessageNotifier = notifiyObj
		}
		err := pingScanner.Scan()
		if err != nil {
			return err
		}
		results := pingScanner.Results().(scanner.PingScanResults)
		printPingScanResults(results.ResultMap)
		if notify {
			err := pingScanner.SendResultsViaNotifier()
			if err != nil {
				return err
			}
		}
	} else {
		tcpFullScanner := scanner.NewTCPFullScanner(scanner.TCPFullScanOptions{
			Targets:             targets,
			TargetPorts:         ports,
			Workers:             uint(numWorkers),
			HostNames:           hostNames,
			AddUnknownHostNames: lookUpHostNames,
			ResponseTimeout:     waitTimeout,
			SkipPingScan:        cmd.Bool("skip-ping"),
			PingTimeout:         cmd.Duration("ping-timeout"),
		})
		if notify {
			tcpFullScanner.MessageNotifier = notifiyObj
		}
		err := tcpFullScanner.Scan()
		if err != nil {
			return err
		}
		PrintTCPFullScanResults(tcpFullScanner)
		if notify {
			err := tcpFullScanner.SendResultsViaNotifier()
			if err != nil {
				return err
			}
		}
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
	printScanResultsMap(tcpFullScanResults.ResultMap)
}

func PrintUDPScanResults(udpScanner *scanner.UDPScanner) {
	var tcpFullScanResults scanner.UDPScanResults
	if results, ok := udpScanner.Results().(scanner.UDPScanResults); ok {
		tcpFullScanResults = results
	} else {
		return
	}
	printScanResultsMap(tcpFullScanResults.ResultMap)
}

func printScanResultsMap(results map[netip.Addr]scanner.HostResult) {
	var tableData [][]string
	for host, hostResults := range results {
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
			tcpService := util.Service(layers.TCPPort(port.Number).String())
			tableData = append(tableData, []string{fmt.Sprintf("%v/%v", port.Protocol, port.Number), port.State.String(), tcpService})
		}
		fmt.Printf("Host is %s\n", hostResults.HostState)
		if hostResults.OpenPorts > 0 {
			pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(tableData).Render()
		}
		fmt.Println("Ports Scanned: ", hostResults.OpenPorts+hostResults.ClosedPorts)
		fmt.Println("Open Ports: ", hostResults.OpenPorts)
		fmt.Println("Closed Ports: ", hostResults.ClosedPorts)
	}
}

func printPingScanResults(results map[netip.Addr]scanner.PingResult) {
	var tableData [][]string
	tableData = pterm.TableData{{"Host", "State"}}
	for host, result := range results {
		hostIdentity := host.String()
		if result.HostName != "" {
			hostIdentity = fmt.Sprintf("%v (%v)", hostIdentity, result.HostName)
		}
		tableData = append(tableData, []string{hostIdentity, result.String()})
	}
	pterm.DefaultTable.WithHasHeader().WithBoxed().WithHeaderRowSeparator("-").WithData(tableData).Render()
}
