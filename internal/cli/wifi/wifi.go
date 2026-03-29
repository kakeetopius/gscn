// Package wifi is used to carry out different operations on a wifi network.
package wifi

import (
	"context"
	"fmt"

	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/kakeetopius/gscn/pkg/scanner"
	"github.com/mdlayher/wifi"
	"github.com/pterm/pterm"
	"github.com/urfave/cli/v3"
)

func RunWifi(clictx context.Context, cmd *cli.Command) error {
	ifaceName := cmd.String("iface")
	autoIface := ifaceName == ""
	notify := cmd.Bool("notify")

	wifiScanner := scanner.NewWiFiScanner(scanner.WiFiScannerOptions{
		AutoInterface: autoIface,
		InterfaceName: ifaceName,
	})

	if notify {
		config, err := util.NewConfig()
		if err != nil {
			return err
		}
		notifierName := config.GetString("notifier.type")
		if notifierName == "" {
			return fmt.Errorf("no notifier type set in the config file")
		}
		notifiyObj, err := notifier.NotifierByName(notifierName, config)
		if err != nil {
			return err
		}
		wifiScanner.MessageNotifier = notifiyObj
	}

	err := wifiScanner.Scan()
	if err != nil {
		return err
	}

	displayWifiScanResults(wifiScanner)

	if notify {
		wifiScanner.SendResultsViaNotifier()
	}
	return nil
}

func displayWifiScanResults(wifiScanner scanner.Scanner) {
	results := wifiScanner.Results().(scanner.WiFiScanResults)

	tableData := pterm.TableData{{"SSID", "BSSID", "Status", "Freq (Mhz)", "Channel", "Strength (dBm)", "Stations"}}
	for _, ap := range results.AccessPoints {
		style := pterm.NewStyle(pterm.FgDefault)
		if ap.Status == wifi.BSSStatusAssociated {
			style = pterm.NewStyle(pterm.Bold)
		}
		ssid := style.Sprint(ap.SSID)
		bssid := style.Sprint(ap.BSSID)
		status := style.Sprint(ap.Status)
		freq := style.Sprint(ap.Frequency)
		channel := style.Sprint(scanner.FreqToChannel(ap.Frequency))
		signal := style.Sprint(ap.Signal / 100)
		stations := style.Sprint(ap.Load.StationCount)

		tableData = append(tableData, []string{ssid, bssid, status, freq, channel, signal, stations})
	}

	pterm.DefaultTable.WithHasHeader().WithHeaderRowSeparator("-").WithBoxed().WithData(tableData).Render()
}
