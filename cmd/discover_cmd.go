package cmd

import (
	"errors"
	"net/netip"
	"time"

	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/kakeetopius/gscn/scanner"
	"github.com/spf13/cobra"
)

func DiscoverCmd() *cobra.Command {
	discoverCmd := cobra.Command{
		Use:     "discover <targets>",
		Short:   "Discover hosts on the local network using ARP for IPv4 or ICMP Neighbour Discovery for IPv6.",
		Aliases: []string{"disc", "d"},
	}

	discoverCmd.AddCommand(
		discoverArpCmd(),
		discoverNDPCmd(),
	)

	return &discoverCmd
}

func discoverArpCmd() *cobra.Command {
	var opts scanner.ARPScanOptions
	var ifaceStrings []string

	arpCmd := cobra.Command{
		Use:   "arp <targets>",
		Short: "Discover hosts on the local network using ARP",
		Example: "\nTargets may be specified as individual IPv4 addresses, IPv4 CIDR ranges, or Non-CIDR ranges e.g.\n" +
			"  gscn discover arp 10.1.1.1\n" +
			"  gscn discover arp 10.1.1.1/24\n" +
			"  gscn discover arp 10.1.1.1-5\n",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetStr := ""
			if len(args) > 0 {
				targetStr = args[0]
			}

			targets, err := getDiscoverTargets(targetStr)
			if err != nil {
				return err
			}
			opts.Targets = targets

			ifaces, err := getDiscoverInterfaces(ifaceStrings)
			if err != nil {
				return err
			}
			opts.Interfaces = ifaces

			arpScanner := scanner.NewARPScanner(opts)
			return doScan(arpScanner)
		},
	}

	arpCmd.Flags().SortFlags = false

	arpCmd.Flags().StringSliceVarP(&ifaceStrings, "iface", "i", nil, "A network interface to find neighbouring hosts from. When used without a target the all the subnets the interface is in are scanned.")
	arpCmd.Flags().DurationVarP(&opts.ResponseTimeout, "response-timeout", "t", 1*time.Second, "Amount of time in seconds to wait for responses.")
	arpCmd.Flags().BoolVarP(&opts.AddUnknownHostNames, "hostnames", "H", false, "Carry out a reverse lookup of the IP addresses discovered on the network to get their host names")
	arpCmd.Flags().BoolVar(&opts.WithVendorInfo, "vendors", true, "Add mac address based vendor information to the results.")

	return &arpCmd
}

func discoverNDPCmd() *cobra.Command {
	var opts scanner.NDPScanOptions
	var ifaceStrings []string

	ndpScan := cobra.Command{
		Use:   "ndp <targets>",
		Short: "Discover hosts on the local network using the IPv6 Neighbour Discovery Protocol.",
		Example: "\nTargets may be specified as individual IPv6 addresses, IPv6 CIDR ranges, or Non-CIDR ranges e.g.\n" +
			"  gscn discover ndp 2001:acad::1\n" +
			"  gscn discover ndp 2001:acad::1/64\n" +
			"  gscn discover ndp 2001:acad::1-10\n",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetStr := ""
			if len(args) > 0 {
				targetStr = args[0]
			}

			targets, err := getDiscoverTargets(targetStr)
			if err != nil {
				return err
			}
			opts.Targets = targets

			ifaces, err := getDiscoverInterfaces(ifaceStrings)
			if err != nil {
				return err
			}
			opts.Interfaces = ifaces

			ndpScanner := scanner.NewNDPScanner(opts)
			return doScan(ndpScanner)
		},
	}

	ndpScan.Flags().SortFlags = false

	ndpScan.Flags().StringSliceVarP(&ifaceStrings, "iface", "i", nil, "A network interface to find neighbouring hosts from. When used without a target the entire subnets the interface is in are scanned.")
	ndpScan.Flags().DurationVarP(&opts.ResponseTimeout, "response-timeout", "t", 1*time.Second, "Amount of time in seconds to wait for responses.")
	ndpScan.Flags().BoolVarP(&opts.AddUnknownHostNames, "hostnames", "H", false, "Carry out a reverse lookup of the IP addresses discovered on the network to get their host names")
	ndpScan.Flags().BoolVar(&opts.FromCache, "from-cache", false, "Discover hosts from the kernel's cached neighbour tables instead of actively probing hosts.")
	ndpScan.Flags().BoolVar(&opts.WithVendorInfo, "vendors", true, "Add mac address based vendor information to the results.")

	return &ndpScan
}

func getDiscoverTargets(targetStr string) ([]netip.Prefix, error) {
	targets, err := scanner.TargetsFromString(targetStr)
	if err != nil {
		if !errors.Is(err, scanner.ErrNoTargets) {
			return []netip.Prefix{}, err
		}
	}

	return targets, nil
}

func getDiscoverInterfaces(ifStrs []string) ([]netutil.Interface, error) {
	ifaces := make([]netutil.Interface, 0, len(ifStrs))
	ifaceProvider := netutil.RealNetInterfaceProvider{}

	for _, ifStr := range ifStrs {
		iface, err := ifaceProvider.InterfaceByName(ifStr)
		if err != nil {
			return nil, err
		}
		err = netutil.VerifyInterface(&ifaceProvider, iface)
		if err != nil {
			return nil, err
		}
		ifaces = append(ifaces, *iface)
	}

	return ifaces, nil
}
