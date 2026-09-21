package cmd

import (
	"context"

	"github.com/kakeetopius/gscn/internal/config"
	"github.com/kakeetopius/gscn/scanner"
	"github.com/spf13/cobra"
)

func WifiCmd() *cobra.Command {
	var opts scanner.WiFiScannerOptions
	wifiCmd := cobra.Command{
		Use:     "wifi",
		Short:   "Carry out different operations on Wi-Fi networks",
		Aliases: []string{"w"},
		RunE: func(cmd *cobra.Command, args []string) error {
			wifiScanner := scanner.NewWiFiScanner(opts)

			appConfig, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			return scanner.DoScan(context.Background(), wifiScanner, scanner.ScanOptions{
				ResultsOutputFile: outputFile,
				PrintJSON:         outputJSON,
				PrintJSONPretty:   jsonPretty,
				Notify:            sendNotification,
				Config:            appConfig,
			})
		},
	}

	wifiCmd.Flags().SortFlags = false

	wifiCmd.Flags().StringVarP(&opts.InterfaceName, "iface", "i", "", "Wi-Fi interface to use when scanning.")
	wifiCmd.Flags().StringSliceVarP(&opts.RequiredSSIDs, "ssids", "s", nil, "Only show results for these SSIDs")

	return &wifiCmd
}
