package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func WifiCmd() *cobra.Command {
	wifiCmd := cobra.Command{
		Use:     "wifi",
		Short:   "Carry out different operations on Wi-Fi networks",
		Aliases: []string{},
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Running wifi")
			return nil
		},
	}

	wifiCmd.Flags().SortFlags = false

	wifiCmd.Flags().StringP("iface", "i", "", "Wi-Fi interface to use when scanning.")
	wifiCmd.Flags().Bool("notify", false, "Send scan results via a configured notifier in $HOME/config/gscn.toml file")

	return &wifiCmd
}
