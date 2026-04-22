package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func DiscoverCmd() *cobra.Command {
	discoverCmd := cobra.Command{
		Use:     "discover",
		Short:   "Discover hosts on the local network using ARP for IPv4 or ICMP Neighbour Discovery for IPv6.",
		Aliases: []string{"d"},
		Example: "\nTargets can be provided in the following formats:\n" +
			"  gscn discover -t 10.1.1.1 # Single Host\n" +
			"  gscn discover -t 10.1.1.1/24 # CIDR Notation\n" +
			"  gscn discover -t 10.1.1.1-5 # IP Range\n" +
			"  gscn discover -t 10.1.1.1,10.2.2.2/24,10.4.4.4-10 # Comma Separated List\n",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Running discover")
			return nil
		},
	}

	discoverCmd.Flags().SortFlags = false
	discoverCmd.PersistentFlags().SortFlags = false

	discoverCmd.Flags().StringP("targert", "t", "", "IP address(es) of the host to scan.")
	discoverCmd.Flags().StringP("iface", "i", "", "A network interface to find neighbouring hosts from. When used without a target the entire subnet the interface is in is scanned.")
	discoverCmd.Flags().StringP("source", "s", "", "Source IP Address to put in the solicting packets.")

	discoverCmd.Flags().DurationP("timeout", "T", 2*time.Second, "Amount of time in seconds to wait for responses.")

	discoverCmd.Flags().BoolP("hostnames", "H", false, "Carry out a reverse lookup on the IP addresses discovered on the network to get their host names")
	discoverCmd.Flags().BoolP("six", "6", false, "Use IPv6's ICMP Neighbor discovery instead of ARP.")
	discoverCmd.Flags().Bool("from-cache", false, "Discover hosts from the kernel's cached neighbour tables instead of actively probing hosts.")
	discoverCmd.Flags().Bool("force-scan", false, "Force scanning of IPv6 networks using ICMPv6 Neighbour Discovery Protocol.")
	discoverCmd.Flags().Bool("notify", false, "Send scan results via a configured notifier in $HOME/config/gscn.toml file or any file passed via --config flag")

	return &discoverCmd
}
