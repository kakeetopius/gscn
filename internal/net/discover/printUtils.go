package discover

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/endobit/oui"
	"github.com/pterm/pterm"
)

func displayDiscoverResults(resultSet []DiscoverResult, withHostNames bool) {
	if len(resultSet) == 0 {
		fmt.Println()
		pterm.Info.Println("Host(s) not found on that network.")
	} else {
		fmt.Println()
		var tableData [][]string
		if withHostNames {
			tableData = pterm.TableData{{"IP Address", "Mac Address", "Vendor", "Host Name"}}
			for _, result := range resultSet {
				tableData = append(tableData, []string{result.ipAddr, result.macAddr, result.vendor, result.hostName})
			}
		} else {
			tableData = pterm.TableData{{"IP Address", "Mac Address", "Vendor"}}
			for _, result := range resultSet {
				tableData = append(tableData, []string{result.ipAddr, result.macAddr, result.vendor})
			}
		}

		pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(tableData).Render()
	}
	fmt.Println("\nPackets Sent: ", packetsSent)
	fmt.Println("Packets Received: ", packetsReceived)
	fmt.Println("Hosts Found: ", len(resultSet))
}

func WaitTimeout(seconds time.Duration, timeoutReason string) {
	if seconds < 1 {
		return
	}
	spinner, err := pterm.DefaultSpinner.Start("Waiting for "+timeoutReason, " timeout")
	if err != nil {
		fmt.Println(err)
	}
	time.Sleep(seconds * time.Second)
	spinner.Success("Timeout Reached.")
}

func addHostNames(resultSet []DiscoverResult, timeout time.Duration) {
	fmt.Println()
	pterm.Info.Println("Trying to resolve hostnames")
	numHosts := len(resultSet)

	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Second)
	defer cancel()

	resolver := net.Resolver{}
	resolver.PreferGo = true

	bar, err := pterm.DefaultProgressbar.WithTotal(numHosts).Start()
	if err != nil {
		fmt.Println(err)
		return
	}
	for i := range resultSet {
		names, err := resolver.LookupAddr(ctx, resultSet[i].ipAddr)
		if err == nil && len(names) > 0 {
			resultSet[i].hostName = names[0]
		}
		bar.Increment()
	}
	bar.Stop()
}

func addVendors(resultSet []DiscoverResult) {
	for i := range resultSet {
		vendor := oui.Vendor(resultSet[i].macAddr)
		if vendor == "" {
			vendor = "(unknown)"
		}
		resultSet[i].vendor = vendor
	}
}
