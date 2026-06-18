package scanner

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/pterm/pterm"
)

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
			service := util.Service(layers.TCPPort(port.Number).String())
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
