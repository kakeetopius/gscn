package discover

import (
	"fmt"
	"time"

	"github.com/pterm/pterm"
)

func displayResults(resultSet []Results, withHostNames bool) {
	if len(resultSet) == 0 {
		fmt.Println()
		pterm.Info.Println("Host(s) not found on that network.")
	} else {
		fmt.Println()
		var tableData [][]string
		if withHostNames {
			tableData = pterm.TableData{{"IP Address", "Mac Address", "Host Name"}}
			for _, result := range resultSet {
				tableData = append(tableData, []string{result.ipAddr, result.macAddr, result.hostName})
			}
		} else {
			tableData = pterm.TableData{{"IP Address", "Mac Address"}}
			for _, result := range resultSet {
				tableData = append(tableData, []string{result.ipAddr, result.macAddr})
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
