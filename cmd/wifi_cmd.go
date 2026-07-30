//go:build linux

package cmd

import (
	"github.com/kakeetopius/gscn/internal/config"
	"github.com/kakeetopius/gscn/scanner"
	"github.com/spf13/cobra"
)

type WifiOpts struct {
	InterfaceString string
	Notify          bool
}

func WifiCmd() *cobra.Command {
	var wifiIface string
	wifiCmd := cobra.Command{
		Use:     "wifi",
		Short:   "Carry out different operations on Wi-Fi networks",
		Aliases: []string{"w"},
		RunE: func(cmd *cobra.Command, args []string) error {
			ifaceName := wifiIface
			autoIface := wifiIface == ""

			wifiScanner := scanner.NewWiFiScanner(scanner.WiFiScannerOptions{
				AutoInterface: autoIface,
				InterfaceName: ifaceName,
			})

			appConfig, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			return scanner.DoScan(wifiScanner, scanner.ScanOptions{
				ResultsOutputFile: outputFile,
				PrintJSON:         outputJSON,
				PrintJSONPretty:   jsonPretty,
				Notify:            sendNotification,
				Config:            appConfig,
			})
		},
	}

	wifiCmd.Flags().SortFlags = false

	wifiCmd.Flags().StringVarP(&wifiIface, "iface", "i", "", "Wi-Fi interface to use when scanning.")

	return &wifiCmd
}
