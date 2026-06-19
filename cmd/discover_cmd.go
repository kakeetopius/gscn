package cmd

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/kakeetopius/gscn/internal/log"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/kakeetopius/gscn/pkg/scanner"
	"github.com/spf13/cobra"
)

func DiscoverCmd() *cobra.Command {
	discoverCmd := cobra.Command{
		Use:     "discover <targets>",
		Short:   "Discover hosts on the local network using ARP for IPv4 or ICMP Neighbour Discovery for IPv6.",
		Aliases: []string{"d"},
	}

	discoverCmd.AddCommand(
		discoverArpCmd(),
		discoverNDPCmd(),
	)

	return &discoverCmd
}

func discoverArpCmd() *cobra.Command {
	var opts scanner.ARPScanOptions
	var ifaceStr string
	var sourceAddr string

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
			targets, iface, err := getTargetsAndIface(targetStr, ifaceStr, false)
			if err != nil {
				return err
			}

			sourceIP, err := getSourceAddr(sourceAddr, iface, targets, false)
			if err != nil {
				return err
			}
			opts.Targets = targets
			opts.Interface = *iface
			opts.Source = sourceIP

			arpScanner := scanner.NewARPScanner(opts)
			return doScan(arpScanner)
		},
	}

	arpCmd.Flags().SortFlags = false

	arpCmd.Flags().StringVarP(&ifaceStr, "iface", "i", "", "A network interface to find neighbouring hosts from. When used without a target the entire subnet the interface is in is scanned.")
	arpCmd.Flags().StringVarP(&sourceAddr, "source", "s", "", "Source IP Address to put in the ARP packets.")
	arpCmd.Flags().DurationVarP(&opts.ResponseTimeout, "response-timeout", "t", 2*time.Second, "Amount of time in seconds to wait for responses.")
	arpCmd.Flags().BoolVarP(&opts.AddUnknownHostNames, "hostnames", "H", false, "Carry out a reverse lookup of the IP addresses discovered on the network to get their host names")
	arpCmd.Flags().BoolVar(&opts.WithVendorInfo, "vendors", true, "Add mac address based vendor information to the results.")

	return &arpCmd
}

func discoverNDPCmd() *cobra.Command {
	var opts scanner.NDPScanOptions
	var ifaceStr string
	var sourceAddr string

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
			targets, iface, err := getTargetsAndIface(targetStr, ifaceStr, true)
			if err != nil {
				return err
			}

			sourceIP, err := getSourceAddr(sourceAddr, iface, targets, true)
			if err != nil {
				return err
			}
			opts.Targets = targets
			opts.Interface = *iface
			opts.Source = sourceIP

			ndpScanner := scanner.NewNDPScanner(opts)
			return doScan(ndpScanner)
		},
	}

	ndpScan.Flags().SortFlags = false

	ndpScan.Flags().StringVarP(&ifaceStr, "iface", "i", "", "A network interface to find neighbouring hosts from. When used without a target the entire subnet the interface is in is scanned.")
	ndpScan.Flags().StringVarP(&sourceAddr, "source", "s", "", "Source IP Address to put in NDP packets.")
	ndpScan.Flags().DurationVarP(&opts.ResponseTimeout, "response-timeout", "t", 2*time.Second, "Amount of time in seconds to wait for responses.")
	ndpScan.Flags().BoolVarP(&opts.AddUnknownHostNames, "hostnames", "H", false, "Carry out a reverse lookup of the IP addresses discovered on the network to get their host names")
	ndpScan.Flags().BoolVar(&opts.FromCache, "from-cache", false, "Discover hosts from the kernel's cached neighbour tables instead of actively probing hosts.")
	ndpScan.Flags().BoolVar(&opts.WithVendorInfo, "vendors", true, "Add mac address based vendor information to the results.")

	return &ndpScan
}

func getTargetsAndIface(targetStr, ifaceStr string, isIP6 bool) ([]netip.Prefix, *util.Interface, error) {
	var iface *util.Interface
	var err error

	logger := log.NewLogger(debug)

	targets := make([]netip.Prefix, 0)
	if targetStr != "" {
		targets, err = scanner.TargetsFromString(targetStr)
		if err != nil {
			return nil, nil, err
		}
	}

	for _, target := range targets {
		if target.Addr().Is6() != isIP6 {
			if isIP6 {
				return nil, nil, fmt.Errorf("%v is not an IPv6 address", target)
			} else {
				return nil, nil, fmt.Errorf("%v is not an IPv4 address", target)
			}
		}
	}

	netInterfaceProvider := util.RealNetInterfaceProvider{}

	if ifaceStr != "" {
		iface, err = netInterfaceProvider.InterfaceByName(ifaceStr)
		if err != nil {
			return nil, nil, err
		}

		var neterr error
		if len(targets) == 0 {
			var target *netip.Prefix
			target, neterr = util.GetFirstIfaceIPNet(&netInterfaceProvider, iface, isIP6)
			if neterr != nil {
				return nil, nil, neterr
			}
			logger.Info("No targets Provided. Scanning for hosts on the interface's network: ", target.Masked())
			fmt.Println()
			targets = append(targets, *target)
		}
	} else {
		// if no interface given we find an interface on the same network as one of the targets.
		for _, target := range targets {
			iface, err = util.GetIfaceByIP(&netInterfaceProvider, target.Addr())
			if err != nil {
				if errors.Is(err, util.ErrNoInterfaceConnectedToTarget) {
					continue
				}
				return nil, nil, err
			}
			break
		}
	}

	if iface == nil {
		return nil, nil, fmt.Errorf("could not determine which interface to use. Use -i option to provide an interface or provide one target with an IP connected to one of the interface networks")
	} else if len(targets) == 0 {
		return nil, nil, fmt.Errorf("could not determine which targets to scan. Use the gscn discover --help for more information")
	}

	err = util.VerifyInterface(&netInterfaceProvider, iface)
	if err != nil {
		return nil, nil, err
	}

	return targets, iface, nil
}

func getSourceAddr(addr string, iface *util.Interface, targets []netip.Prefix, ip6 bool) (netip.Addr, error) {
	var sourceAddr netip.Addr
	netInterfaceProvider := util.RealNetInterfaceProvider{}

	if addr != "" {
		source, err := netip.ParseAddr(addr)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("error parsing source address :%v", err)
		}
		sourceAddr = source
	} else {
		source, err := util.GetSourceIPFromInterface(&netInterfaceProvider, iface, targets, ip6)
		if err != nil {
			return netip.Addr{}, err
		}
		sourceAddr = *source
	}

	return sourceAddr, nil
}
