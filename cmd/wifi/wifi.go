// Package wifi is used to carry out different operations on a wifi network.
package wifi

import (
	"fmt"

	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/kakeetopius/gscn/pkg/scanner"
	"github.com/mdlayher/wifi"
	"github.com/pterm/pterm"
	"github.com/spf13/viper"
)

type WifiOpts struct {
	Config          *viper.Viper
	InterfaceString string
	Notify          bool
}

func RunWifi(opts WifiOpts) error {
	ifaceName := opts.InterfaceString
	autoIface := ifaceName == ""

	wifiScanner := scanner.NewWiFiScanner(scanner.WiFiScannerOptions{
		AutoInterface: autoIface,
		InterfaceName: ifaceName,
	})

	if opts.Notify {
		notifierName := opts.Config.GetString("notifier.type")
		if notifierName == "" {
			return fmt.Errorf("no notifier type set in the config file")
		}
		notifiyObj, err := notifier.NotifierByName(notifierName, opts.Config)
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

	if opts.Notify {
		err := wifiScanner.SendResultsViaNotifier()
		if err != nil {
			return err
		}
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
