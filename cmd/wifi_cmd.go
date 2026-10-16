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

			config, err := config.New(configPath(cmd), rootCmdConfigSetup(cmd))
			if err != nil {
				return err
			}
			err = config.Load()
			if err != nil {
				return err
			}

			return DoScan(context.Background(), wifiScanner, config)
		},
	}

	wifiCmd.Flags().SortFlags = false

	wifiCmd.Flags().StringVarP(&opts.InterfaceName, "iface", "i", "", "Wi-Fi interface to use when scanning.")
	wifiCmd.Flags().StringSliceVarP(&opts.RequiredSSIDs, "ssids", "s", nil, "Only show results for these SSIDs")

	return &wifiCmd
}
