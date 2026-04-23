// Package scan is used to get various network information about hosts on a network.
package scan

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/kakeetopius/gscn/pkg/scanner"
	"github.com/pterm/pterm"
	"github.com/spf13/viper"
)

type ScanOpts struct {
	Config           *viper.Viper
	TargetsString    string
	PortsString      string
	Workers          int
	ResponseTimeout  time.Duration
	PingTimeout      time.Duration
	ResolveHostNames bool
	DoPingScan       bool
	DoUDPScan        bool
	SkipPingScan     bool
	Notify           bool
}

func RunScan(opts ScanOpts) error {
	var err error
	targets := make([]netip.Prefix, 0)
	ports := make([]uint, 0)
	var hostNames map[netip.Addr]string

	numWorkers := opts.Workers
	if numWorkers > 500 {
		return fmt.Errorf("number of workers cannot go above 500")
	}

	if targetStr := opts.TargetsString; targetStr != "" {
		targets, hostNames, err = scanner.TargetsFromStringWithDNSLookup(targetStr)
		if err != nil {
			return err
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("no hosts to scan provided")
	}
	if portStr := opts.PortsString; portStr != "" {
		ports, err = scanner.PortsFromString(portStr)
		if err != nil {
			return err
		}
	}
	if len(ports) == 0 && !opts.DoPingScan {
		return fmt.Errorf("no ports to scan provided")
	}

	notify := opts.Notify
	var notifiyObj notifier.Notifier
	if notify {
		config := opts.Config
		notifierName := config.GetString("notifier.type")
		if notifierName == "" {
			return fmt.Errorf("no notifier type set in the config file")
		}
		notifiyObj, err = notifier.NotifierByName(notifierName, config)
		if err != nil {
			return err
		}
	}
	if opts.DoUDPScan {
		udpScanner := scanner.NewUDPScanner(scanner.UDPScanOptions{
			Targets:             targets,
			TargetPorts:         ports,
			Workers:             uint(numWorkers),
			HostNames:           hostNames,
			AddUnknownHostNames: opts.ResolveHostNames,
			ResponseTimeout:     opts.ResponseTimeout,
			PingTimeout:         opts.PingTimeout,
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

	} else if opts.DoPingScan {
		pingScanner := scanner.NewPingScanner(scanner.PingScanOptions{
			Targets:             targets,
			PingTimeout:         opts.PingTimeout,
			AddUnknownHostNames: opts.ResolveHostNames,
			HostNames:           hostNames,
			Workers:             numWorkers,
		})
		if notify {
			pingScanner.MessageNotifier = notifiyObj
		}
		err := pingScanner.Scan()
		if err != nil {
			return err
		}
		results := pingScanner.Results().(scanner.PingScanResults)
		stats := pingScanner.Stats().(scanner.PingStats)
		printPingScanResults(results, stats)
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
			AddUnknownHostNames: opts.ResolveHostNames,
			ResponseTimeout:     opts.ResponseTimeout,
			SkipPingScan:        opts.SkipPingScan,
			PingTimeout:         opts.PingTimeout,
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
	totalHosts := len(results)
	totalUp := 0
	for host, hostResults := range results {
		tableData = pterm.TableData{{"Port", "State", "Service"}}
		name := ""
		if hostResults.HostName != "" {
			name = fmt.Sprintf("(%v)", hostResults.HostName)
		}
		if hostResults.HostState == scanner.HostStateDown && totalHosts > 10 {
			continue
		}
		if hostResults.HostState == scanner.HostStateUp {
			totalUp++
		}
		fmt.Printf("\nScan Report for %v %v\n", host, name)

		totalPortsScanned := hostResults.TotalNumberOfPorts()
		for _, port := range hostResults.Ports {
			if port.State == scanner.PortStateClosed && totalPortsScanned > 10 {
				continue // no need to add closed port to table if scanned ports are above 10
			}
			service := util.Service(layers.TCPPort(port.Number).String())
			tableData = append(tableData, []string{fmt.Sprintf("%v/%v", port.Protocol, port.Number), port.State.String(), service})
		}

		hostStateStyle := pterm.FgDefault
		switch hostResults.HostState {
		case scanner.HostStateUp:
			hostStateStyle = pterm.FgGreen
		case scanner.HostStateDown:
			hostStateStyle = pterm.FgRed
		}
		fmt.Printf("Host State: %s\n", hostStateStyle.Sprint(hostResults.HostState))
		if len(tableData) > 1 && hostResults.HostState == scanner.HostStateUp {
			pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(tableData).Render()
		}
		fmt.Println("Ports Scanned: ", totalPortsScanned)
		fmt.Println("Open Ports: ", hostResults.OpenPorts)
		fmt.Println("Closed Ports: ", hostResults.ClosedPorts)
		if hostResults.FilteredPorts > 0 {
			fmt.Println("Filtered Ports: ", hostResults.FilteredPorts)
		}
	}
	fmt.Println("\n──────────────────────────────────────────────")
	fmt.Printf("Total Hosts Scanned: %v\n", totalHosts)
	fmt.Printf("Hosts that are Up: %v\n", totalUp)
	fmt.Printf("Hosts that are down: %v\n", totalHosts-totalUp)
}

func printPingScanResults(results scanner.PingScanResults, stats scanner.PingStats) {
	var tableData [][]string
	tableData = pterm.TableData{{"Host", "State"}}
	totalHosts := stats.DownHosts + stats.UpHosts
	for host, result := range results.ResultMap {
		hostIdentity := host.String()
		if result.HostState == scanner.HostStateDown && totalHosts > 256 {
			continue
		}
		if result.HostName != "" {
			hostIdentity = fmt.Sprintf("%v (%v)", hostIdentity, result.HostName)
		}
		hostStateStyle := pterm.FgDefault
		switch result.HostState {
		case scanner.HostStateUp:
			hostStateStyle = pterm.FgGreen
		case scanner.HostStateDown:
			hostStateStyle = pterm.FgRed
		}
		tableData = append(tableData, []string{hostIdentity, hostStateStyle.Sprint(result.HostState)})
	}
	if len(tableData) > 1 {
		pterm.DefaultTable.WithHasHeader().WithBoxed().WithHeaderRowSeparator("-").WithData(tableData).Render()
	}
	fmt.Println("\nTotal Hosts Scanned: ", totalHosts)
	fmt.Println("Hosts that are Up: ", stats.UpHosts)
	fmt.Println("Hosts that are down: ", stats.DownHosts)
}
