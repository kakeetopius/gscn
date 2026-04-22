package discover

import (
	"fmt"

	"github.com/kakeetopius/gscn/pkg/scanner"
	"github.com/pterm/pterm"
)

func displayARPResults(arpResults *scanner.ARPScanResults, arpStats *scanner.ARPScanStats) {
	if len(arpResults.ResultSet) == 0 {
		fmt.Println()
		pterm.Info.Println("Host(s) not found on that network.")
	} else {
		fmt.Println()
		var tableData [][]string
		if arpResults.HasHostNames() {
			tableData = pterm.TableData{{"IP Address", "Mac Address", "Vendor", "Host Name"}}
		} else {
			tableData = pterm.TableData{{"IP Address", "Mac Address", "Vendor"}}
		}

		for _, result := range arpResults.ResultSet {
			vendor := result.Vendor
			if vendor == "" {
				vendor = "(unknown)"
			}
			if arpResults.HasHostNames() {
				hostName := result.HostName
				if hostName == "" {
					hostName = "(unknown)"
				}
				tableData = append(tableData, []string{result.IPAddr, result.MacAddr, vendor, hostName})
				continue
			}
			tableData = append(tableData, []string{result.IPAddr, result.MacAddr, vendor})
		}
		pterm.DefaultTable.WithHasHeader().WithHeaderRowSeparator("*").WithBoxed().WithData(tableData).Render()
	}
	if arpStats != nil {
		fmt.Println("\nPackets Sent: ", arpStats.PacketsSent)
		fmt.Println("Packets Received: ", arpStats.PacketsReceived)
		fmt.Println("Hosts Found: ", len(arpResults.ResultSet))

	}
}

func displayNDPResults(ndpResults *scanner.NDPScanResults, ndpStats *scanner.NDPScanStats) {
	if len(ndpResults.ResultSet) == 0 {
		fmt.Println()
		pterm.Info.Println("Host(s) not found on that network.")
	} else {
		fmt.Println()
		var tableData [][]string
		if ndpResults.HasHostNames() {
			tableData = pterm.TableData{{"IP Address", "Mac Address", "Vendor", "Host Name"}}
		} else {
			tableData = pterm.TableData{{"IP Address", "Mac Address", "Vendor"}}
		}

		for _, result := range ndpResults.ResultSet {
			vendor := result.Vendor
			if vendor == "" {
				vendor = "(unknown)"
			}
			if ndpResults.HasHostNames() {
				hostName := result.HostName
				if hostName == "" {
					hostName = "(unknown)"
				}
				tableData = append(tableData, []string{result.IPAddr, result.MacAddr, vendor, hostName})
				continue
			}
			tableData = append(tableData, []string{result.IPAddr, result.MacAddr, vendor})
		}
		pterm.DefaultTable.WithHasHeader().WithHeaderRowSeparator("*").WithBoxed().WithData(tableData).Render()
	}

	if ndpStats != nil {
		fmt.Println("\nPackets Sent: ", ndpStats.PacketsSent)
		fmt.Println("Packets Received: ", ndpStats.PacketsReceived)
		fmt.Println("Hosts Found: ", len(ndpResults.ResultSet))
	}
}
