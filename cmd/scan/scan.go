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
	PingCount        int
	ResponseTimeout  time.Duration
	PingTimeout      time.Duration
	ResolveHostNames bool
	DoPingScan       bool
	DoUDPScan        bool
	SkipPingScan     bool
	PrintOnlyOpen    bool
	PrintOnlyUp      bool
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
			PingCount:           opts.PingCount,
		})
		if notify {
			udpScanner.MessageNotifier = notifiyObj
		}
		err := udpScanner.Scan()
		if err != nil {
			return err
		}
		PrintUDPScanResults(udpScanner, &opts)
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
			PingCount:           opts.PingCount,
		})
		if notify {
			pingScanner.MessageNotifier = notifiyObj
		}
		err := pingScanner.Scan()
		if err != nil {
			return err
		}
		results := pingScanner.SortedResults()
		stats := pingScanner.Stats().(scanner.PingStats)
		printPingScanResults(results, stats, &opts)
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
			PingCount:           opts.PingCount,
		})
		if notify {
			tcpFullScanner.MessageNotifier = notifiyObj
		}
		err := tcpFullScanner.Scan()
		if err != nil {
			return err
		}
		PrintTCPFullScanResults(tcpFullScanner, &opts)
		if notify {
			err := tcpFullScanner.SendResultsViaNotifier()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func PrintTCPFullScanResults(tcpFullScanner *scanner.TCPFullScanner, opts *ScanOpts) {
	var tcpFullScanResults scanner.TCPFullScanResults
	if results, ok := tcpFullScanner.Results().(scanner.TCPFullScanResults); ok {
		tcpFullScanResults = results
	} else {
		return
	}
	printScanResultsMap(tcpFullScanResults.ResultMap, opts)
}

func PrintUDPScanResults(udpScanner *scanner.UDPScanner, opts *ScanOpts) {
	var tcpFullScanResults scanner.UDPScanResults
	if results, ok := udpScanner.Results().(scanner.UDPScanResults); ok {
		tcpFullScanResults = results
	} else {
		return
	}
	printScanResultsMap(tcpFullScanResults.ResultMap, opts)
}

func printScanResultsMap(results map[netip.Addr]scanner.HostResult, opts *ScanOpts) {
	var tableData [][]string
	totalHosts := len(results)
	totalUp := 0
	for host, hostResults := range results {
		if hostResults.HostState == scanner.HostStateDown && opts.PrintOnlyUp {
			continue
		}

		tableData = pterm.TableData{{"Port", "State", "Service"}}
		name := ""
		if hostResults.HostName != "" {
			name = fmt.Sprintf("(%v)", hostResults.HostName)
		}
		if hostResults.HostState == scanner.HostStateDown && totalHosts > 10 {
			continue // do not print hosts that are down if total hosts are above 10
		}
		if hostResults.HostState == scanner.HostStateUp {
			totalUp++
		}
		fmt.Printf("\nScan Report for %v %v\n", host, name)

		totalPortsScanned := hostResults.TotalNumberOfPorts()
		for _, port := range hostResults.Ports {
			if port.State == scanner.PortStateClosed && opts.PrintOnlyOpen {
				continue
			}
			if port.State == scanner.PortStateClosed && totalPortsScanned > 10 {
				continue // do not add closed ports to table if scanned ports are above 10
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
		fmt.Println("Average RTT: ", hostResults.AverageRTT.Truncate(time.Microsecond))
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
	fmt.Printf("Hosts that are down: %v\n\n", totalHosts-totalUp)
}

func printPingScanResults(results []scanner.PingResult, stats scanner.PingStats, opts *ScanOpts) {
	var tableData [][]string
	tableData = pterm.TableData{{"Host", "State", "Average RTT"}}
	totalHosts := stats.DownHosts + stats.UpHosts
	for _, result := range results {
		if result.HostState == scanner.HostStateDown && opts.PrintOnlyUp {
			continue
		}

		hostIdentity := result.IP.String()
		if result.HostState == scanner.HostStateDown && totalHosts > 256 {
			continue // do not add hosts that are down if scanned hosts are above 10
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
		tableData = append(tableData, []string{hostIdentity, hostStateStyle.Sprint(result.HostState), result.AverageRTT.Truncate(time.Microsecond).String()})
	}
	if len(tableData) > 1 {
		pterm.DefaultTable.WithHasHeader().WithBoxed().WithHeaderRowSeparator("-").WithData(tableData).Render()
	}
	fmt.Println("\nTotal Hosts Scanned: ", totalHosts)
	fmt.Println("Hosts that are Up: ", stats.UpHosts)
	fmt.Printf("Hosts that are down: %v\n\n", stats.DownHosts)
}
