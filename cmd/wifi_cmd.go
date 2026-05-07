package cmd

import (
	"github.com/kakeetopius/gscn/cmd/wifi"
	"github.com/spf13/cobra"
)

// go: build linux

var wifiIface string

func WifiCmd() *cobra.Command {
	wifiCmd := cobra.Command{
		Use:     "wifi",
		Short:   "Carry out different operations on Wi-Fi networks",
		Aliases: []string{},
		RunE: func(cmd *cobra.Command, args []string) error {
			return wifi.RunWifi(wifi.WifiOpts{
				Config:          config,
				InterfaceString: wifiIface,
				Notify:          notify,
			})
		},
	}

	wifiCmd.Flags().SortFlags = false

	wifiCmd.Flags().StringVarP(&wifiIface, "iface", "i", "", "Wi-Fi interface to use when scanning.")

	return &wifiCmd
}
