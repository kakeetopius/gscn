package cmd

import (
	"time"

	"github.com/kakeetopius/gscn/cmd/discover"
	"github.com/spf13/cobra"
)

func DiscoverCmd() *cobra.Command {
	var discoverOpts discover.DiscoverOpts
	discoverOpts.Debug = true

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
			discoverOpts.Notify = true
			discoverOpts.Config = config
			return discover.RunDiscover(discoverOpts)
		},
	}

	discoverCmd.Flags().SortFlags = false
	discoverCmd.PersistentFlags().SortFlags = false

	discoverCmd.Flags().StringVarP(&discoverOpts.TargetsString, "target", "t", "", "IP address(es) of the host to scan.")
	discoverCmd.Flags().StringVarP(&discoverOpts.InterfaceString, "iface", "i", "", "A network interface to find neighbouring hosts from. When used without a target the entire subnet the interface is in is scanned.")
	discoverCmd.Flags().StringVarP(&discoverOpts.SourceAddrString, "source", "s", "", "Source IP Address to put in the solicting packets.")

	discoverCmd.Flags().DurationVarP(&discoverOpts.Timeout, "response-timeout", "T", 2*time.Second, "Amount of time in seconds to wait for responses.")

	discoverCmd.Flags().BoolVarP(&discoverOpts.ResolveHostnames, "hostnames", "H", false, "Carry out a reverse lookup of the IP addresses discovered on the network to get their host names")
	discoverCmd.Flags().BoolVarP(&discoverOpts.UseIP6, "six", "6", false, "Use IPv6's ICMP Neighbor discovery instead of ARP.")
	discoverCmd.Flags().BoolVar(&discoverOpts.FromCache, "from-cache", false, "Discover hosts from the kernel's cached neighbour tables instead of actively probing hosts.")
	discoverCmd.Flags().BoolVar(&discoverOpts.ForceIP6Scan, "force-scan", false, "Force scanning of IPv6 networks using ICMPv6 Neighbour Discovery Protocol.")

	return &discoverCmd
}
