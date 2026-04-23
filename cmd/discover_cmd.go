package cmd

import (
	"time"

	"github.com/kakeetopius/gscn/cmd/discover"
	"github.com/spf13/cobra"
)

var (
	targetStr        string
	ifaceStr         string
	sourceAddr       string
	timeout          time.Duration
	resolveHostnames bool
	useIP6           bool
	fromCache        bool
	forceScan        bool
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
			return discover.RunDiscover(discover.DiscoverOpts{
				Config:           config,
				TargetsString:    targetStr,
				InterfaceString:  ifaceStr,
				SourceAddrString: sourceAddr,
				Timeout:          timeout,
				ResolveHostnames: resolveHostnames,
				UseIP6:           useIP6,
				FromCache:        fromCache,
				ForceIP6Scan:     forceScan,
				Notify:           notify,
			})
		},
	}

	discoverCmd.Flags().SortFlags = false
	discoverCmd.PersistentFlags().SortFlags = false

	discoverCmd.Flags().StringVarP(&targetStr, "target", "t", "", "IP address(es) of the host to scan.")
	discoverCmd.Flags().StringVarP(&ifaceStr, "iface", "i", "", "A network interface to find neighbouring hosts from. When used without a target the entire subnet the interface is in is scanned.")
	discoverCmd.Flags().StringVarP(&sourceAddr, "source", "s", "", "Source IP Address to put in the solicting packets.")

	discoverCmd.Flags().DurationVarP(&timeout, "response-timeout", "T", 2*time.Second, "Amount of time in seconds to wait for responses.")

	discoverCmd.Flags().BoolVarP(&resolveHostnames, "hostnames", "H", false, "Carry out a reverse lookup of the IP addresses discovered on the network to get their host names")
	discoverCmd.Flags().BoolVarP(&useIP6, "six", "6", false, "Use IPv6's ICMP Neighbor discovery instead of ARP.")
	discoverCmd.Flags().BoolVar(&fromCache, "from-cache", false, "Discover hosts from the kernel's cached neighbour tables instead of actively probing hosts.")
	discoverCmd.Flags().BoolVar(&forceScan, "force-scan", false, "Force scanning of IPv6 networks using ICMPv6 Neighbour Discovery Protocol.")

	return &discoverCmd
}
