package cmd

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/kakeetopius/gscn/internal/config"
	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/kakeetopius/gscn/scanner"
	"github.com/spf13/cobra"
)

func DiscoverCmd() *cobra.Command {
	discoverCmd := cobra.Command{
		Use: "discover <targets>",
		Example: "\nTargets for commands that require them may be specified as individual IPv4 addresses, IPv4 CIDR ranges, or Non-CIDR ranges e.g.\n" +
			"  gscn discover <discover-type> 10.1.1.1\n" +
			"  gscn discover <discover-type> 10.1.1.1/24\n" +
			"  gscn discover <discover-type> 10.1.1.1-5\n" +
			"  gscn discover <discover-type> 2001:acad::1\n",
		Short:   "Discover hosts on the local network using ARP for IPv4 or ICMPv6 Neighbour Discovery for IPv6.",
		Aliases: []string{"disc", "d"},
	}

	discoverCmd.AddCommand(
		discoverArpCmd(),
		discoverNDPCmd(),
		discoverDHCPv4Cmd(),
	)

	return &discoverCmd
}

func discoverArpCmd() *cobra.Command {
	var opts scanner.ARPScanOptions
	var ifaceStrings []string

	arpCmd := cobra.Command{
		Use:   "arp <targets>",
		Short: "Discover hosts on the local network using the Address Resolution Protocol.",
		RunE: func(cmd *cobra.Command, args []string) error {
			appConfig, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			targets, err := getDiscoverTargets(args)
			if err != nil {
				return err
			}
			opts.Targets = targets

			ifaces, err := getDiscoverInterfaces(ifaceStrings)
			if err != nil {
				return err
			}
			opts.Interfaces = ifaces
			opts.Verbose = true

			arpScanner, err := scanner.NewARPScanner(opts)
			if err != nil {
				return err
			}

			return scanner.DoScan(context.Background(), arpScanner, scanner.ScanOptions{
				ResultsOutputFile: outputFile,
				PrintJSON:         outputJSON,
				PrintJSONPretty:   jsonPretty,
				Notify:            sendNotification,
				Config:            appConfig,
			})
		},
	}

	arpCmd.Flags().SortFlags = false

	arpCmd.Flags().StringSliceVarP(&ifaceStrings, "iface", "i", nil, "A network interface to find neighbouring hosts from. When used without a target the all the subnets the interface is in are scanned.")
	arpCmd.Flags().UintVarP(&opts.ProbeCount, "count", "c", 4, "The number of ARP requests to send for each host")
	arpCmd.Flags().BoolVarP(&opts.Passive, "passive", "p", false, "Do not send any ARP packets rather passively listen for ARP replies from the given targets.")
	arpCmd.Flags().DurationVarP(&opts.ResponseTimeout, "response-timeout", "t", 2*time.Second, "Amount of time in seconds to wait for responses.")
	arpCmd.Flags().BoolVarP(&opts.AddUnknownHostNames, "hostnames", "H", false, "Carry out a reverse lookup of the IP addresses discovered on the network to get their host names")
	arpCmd.Flags().BoolVar(&opts.WithVendorInfo, "vendors", true, "Add mac address based vendor information to the results.")
	arpCmd.Flags().BoolVar(&opts.FromCache, "from-cache", false, "Discover hosts from the kernel's cached neighbour tables instead of actively probing hosts.")

	return &arpCmd
}

func discoverNDPCmd() *cobra.Command {
	var opts scanner.NDPScanOptions
	var iface string

	ndpScan := cobra.Command{
		Use:   "ndp <targets>",
		Short: "Discover hosts on the local network using the ICMPv6 Neighbour Discovery Protocol.",
		RunE: func(cmd *cobra.Command, args []string) error {
			appConfig, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			targets, err := getDiscoverTargets(args)
			if err != nil {
				return err
			}
			opts.Targets = targets
			opts.Verbose = true

			ifaces, err := getDiscoverInterfaces([]string{iface})
			if err != nil {
				return err
			}
			if len(ifaces) != 0 {
				opts.Interface = &ifaces[0]
			}

			ndpScanner, err := scanner.NewNDPScanner(opts)
			if err != nil {
				return err
			}
			return scanner.DoScan(context.Background(), ndpScanner, scanner.ScanOptions{
				ResultsOutputFile: outputFile,
				PrintJSON:         outputJSON,
				PrintJSONPretty:   jsonPretty,
				Notify:            sendNotification,
				Config:            appConfig,
			})
		},
	}

	ndpScan.Flags().SortFlags = false

	ndpScan.Flags().StringVarP(&iface, "iface", "i", "", "A network interface to find neighbouring hosts from. When used without a target the entire subnets the interface is in are scanned.")
	ndpScan.Flags().UintVarP(&opts.ProbeCount, "count", "c", 4, "The number of ICMPv6 Neighbour Solicitation Packets to send for each host")
	ndpScan.Flags().BoolVarP(&opts.Passive, "passive", "p", false, "Do not send any ICMPv6 Neighbour Solicitation packets rather passively listen for Neighbor Advertisements from the given targets.")
	ndpScan.Flags().DurationVarP(&opts.ResponseTimeout, "response-timeout", "t", 1*time.Second, "Amount of time in seconds to wait for responses.")
	ndpScan.Flags().BoolVarP(&opts.AddUnknownHostNames, "hostnames", "H", false, "Carry out a reverse lookup of the IP addresses discovered on the network to get their host names")
	ndpScan.Flags().BoolVar(&opts.FromCache, "from-cache", false, "Discover hosts from the kernel's cached neighbour tables instead of actively probing hosts.")
	ndpScan.Flags().BoolVar(&opts.WithVendorInfo, "vendors", true, "Add mac address based vendor information to the results.")

	ndpScan.MarkFlagRequired("iface")

	return &ndpScan
}

func discoverDHCPv4Cmd() *cobra.Command {
	var opts scanner.DHCPv4ScannerOpts
	var ifaceStrings []string

	dhcpCmd := cobra.Command{
		Use:   "dhcp",
		Short: "Discover dhcpv4 servers on the connected networks.",
		RunE: func(cmd *cobra.Command, args []string) error {
			appConfig, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			ifaces, err := getDiscoverInterfaces(ifaceStrings)
			if err != nil {
				return err
			}
			opts.Interfaces = ifaces
			opts.Verbose = true

			arpScanner, err := scanner.NewDHCPv4ServerScanner(opts)
			if err != nil {
				return err
			}

			return scanner.DoScan(context.Background(), arpScanner, scanner.ScanOptions{
				ResultsOutputFile: outputFile,
				PrintJSON:         outputJSON,
				PrintJSONPretty:   jsonPretty,
				Notify:            sendNotification,
				Config:            appConfig,
			})
		},
	}

	dhcpCmd.Flags().SortFlags = false

	dhcpCmd.Flags().StringSliceVarP(&ifaceStrings, "iface", "i", nil, "A network interface to find dhcp servers from. If omitted, all interfaces are used.")
	dhcpCmd.Flags().BoolVarP(&opts.Passive, "passive", "p", false, "Do not send any DHCPDiscover packets rather passively listen for DHCPOffers on the network.")
	dhcpCmd.Flags().DurationVarP(&opts.ResponseTimeout, "response-timeout", "t", 2*time.Second, "Amount of time in seconds to wait for responses.")
	dhcpCmd.Flags().BoolVarP(&opts.WithHostNames, "hostnames", "H", false, "Carry out a reverse lookup of the IP addresses of the dhcpv4 servers discovered on the network")
	dhcpCmd.Flags().BoolVar(&opts.WithVendorInfo, "vendors", true, "Add mac address based vendor information to the results.")

	return &dhcpCmd
}

func getDiscoverTargets(targetStrs []string) ([]netip.Prefix, error) {
	targets, err := scanner.TargetsFromString(targetStrs)
	if err != nil {
		if !errors.Is(err, scanner.ErrNoTargets) {
			return []netip.Prefix{}, err
		}
	}

	return targets, nil
}

func getDiscoverInterfaces(ifStrs []string) ([]netutil.Interface, error) {
	ifaces := make([]netutil.Interface, 0, len(ifStrs))
	ifaceProvider, err := netutil.InterfaceProvider()
	if err != nil {
		return nil, err
	}

	for _, ifStr := range ifStrs {
		iface, err := ifaceProvider.InterfaceByName(ifStr)
		if err != nil {
			return nil, err
		}
		err = netutil.VerifyInterface(&iface)
		if err != nil {
			return nil, err
		}
		ifaces = append(ifaces, iface)
	}

	return ifaces, nil
}
