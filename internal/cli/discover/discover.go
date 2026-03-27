// Package discover is used to discover hosts on a network using ARP for IPv4 or ICMPv6 Neigbour Discovery for IPv6.
package discover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/kakeetopius/gscn/pkg/scanner"
	"github.com/pterm/pterm"
	"github.com/urfave/cli/v3"
)

type DiscoverOpts struct {
	cmd     *cli.Command
	targets []netip.Prefix
	iface   *net.Interface
	source  netip.Addr
}

type RealNetInterfaceProvider struct{}

func (RealNetInterfaceProvider) Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}

func (RealNetInterfaceProvider) AddrsOf(iface *net.Interface) ([]net.Addr, error) {
	return iface.Addrs()
}

func RunDiscover(ctx context.Context, cmd *cli.Command) error {
	var iface *net.Interface
	var err error
	discoverOpts := DiscoverOpts{
		cmd: cmd,
	}

	useIP6 := cmd.Bool("six")

	targets := make([]netip.Prefix, 0)
	if targetStr := cmd.String("target"); targetStr != "" {
		targets, err = scanner.TargetsFromString(targetStr)
		if err != nil {
			return err
		}
	}

	netInterfaceProvider := RealNetInterfaceProvider{}

	if ifaceName := cmd.String("iface"); ifaceName != "" {
		iface, err = net.InterfaceByName(ifaceName)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			var target *netip.Prefix
			target, err = util.GetFirstIfaceIPNet(netInterfaceProvider, iface, useIP6)
			if err != nil {
				return err
			}
			pterm.Info.Println("No targets Provided. Scanning for hosts on the interface's network: ", target.Masked())
			fmt.Println()
			targets = append(targets, *target)
		}
	} else {
		if len(targets) == 0 {
			return fmt.Errorf("could not determine which hosts scan. Use gscn discover --help for mor information")
		}
		for _, target := range targets {
			iface, err = util.GetIfaceByIP(netInterfaceProvider, target.Addr())
			if err != nil {
				if errors.Is(err, util.ErrNoInterfaceConnectedToTarget) {
					continue
				}
				return err
			}
			break
		}
	}

	if iface == nil {
		return fmt.Errorf("could not determine which interface to use. Use -i option to provide an interface or provide one target with an IP connected to one of the interface networks")
	} else if len(targets) == 0 {
		return fmt.Errorf("could not determine which targets to scan. Use the gscn discover --help for more information")
	}
	err = util.VerifyInterface(netInterfaceProvider, iface)
	if err != nil {
		return err
	}

	var sourceAddr netip.Addr
	if source := cmd.String("source"); source != "" {
		source, parseerr := netip.ParseAddr(source)
		if parseerr != nil {
			return fmt.Errorf("error parsing source address :%v", parseerr)
		}
		sourceAddr = source
	} else {
		source, nerr := util.GetSourceIPFromInterface(netInterfaceProvider, iface, targets, useIP6)
		if nerr != nil {
			return err
		}
		sourceAddr = *source
	}

	discoverOpts.targets = targets
	discoverOpts.iface = iface
	discoverOpts.source = sourceAddr

	if useIP6 {
		err = runIP6Discovery(&discoverOpts)
	} else {
		err = runIP4Discovery(&discoverOpts)
	}

	return err
}

func runIP4Discovery(opts *DiscoverOpts) error {
	for _, target := range opts.targets {
		if !target.Addr().Is4() {
			return fmt.Errorf("%v is not an IPv4 address", target)
		}
	}
	timeout := opts.cmd.Duration("timeout")
	arpScanner := scanner.NewARPScanner(&scanner.ARPScanOptions{
		Targets:   opts.targets,
		Source:    opts.source,
		Interface: *opts.iface,
	}).WithTimeout(timeout).WithVendorInfo()

	if opts.cmd.Bool("notify") {
		config, confErr := util.SetUpConfig()
		if confErr != nil {
			return confErr
		}
		notifierName := config.GetString("notifier.type")
		if notifierName == "" {
			return fmt.Errorf("no notifier type set in the config file")
		}
		notifierObj, err := notifier.NotifierByName(notifierName, config)
		if err != nil {
			return err
		}
		arpScanner = arpScanner.WithNotifier(notifierObj)
	}
	if opts.cmd.Bool("hostnames") {
		arpScanner = arpScanner.WithHostNames(nil, true)
	}
	err := arpScanner.Scan()
	if err != nil {
		return err
	}
	var arpResults scanner.ARPScanResults
	if results, ok := arpScanner.Results().(scanner.ARPScanResults); ok {
		arpResults = results
	} else {
		return fmt.Errorf("error getting ARP results")
	}
	var arpStats scanner.ARPScanStats
	if stats, ok := arpScanner.Stats().(scanner.ARPScanStats); ok {
		arpStats = stats
	} else {
		return fmt.Errorf("error getting ARP stats")
	}
	displayARPResults(&arpResults, &arpStats)
	if opts.cmd.Bool("notify") {
		err = arpScanner.SendResultsViaNotifier()
		if err != nil {
			return err
		}
	}
	return nil
}

func runIP6Discovery(opts *DiscoverOpts) error {
	useCache := opts.cmd.Bool("from-cache")
	forceScan := opts.cmd.Bool("force-scan")
	for _, target := range opts.targets {
		if !target.Addr().Is6() {
			return fmt.Errorf("%v is not an IPv6 address", target)
		}
		if target.Bits() != 128 {
			if !useCache && !forceScan {
				fmt.Println()
				pterm.Warning.Printf("Scanning of an IPv6 network %v using ICMPv6 NDP is impractical due to its large subnets\n", target.Masked())
				pterm.Info.Println("To discover hosts using the kernel's neighbour table use the option --from-cache.")
				pterm.Info.Println("To force scanning of the IPv6 subnet use the option --force-scan.")
				return nil
			}
		}
	}
	if useCache {
		pterm.Info.Println("Discovering Host(s) using kernel's neighbour table for interface ", opts.iface.Name)
		results, nerr := NDPResultsUsingNetlink(opts.iface, opts.targets)
		if nerr != nil {
			return nerr
		}
		displayNDPResults(results, nil)
		return nil
	}
	if forceScan {
		pterm.Warning.Println("Scanning of IPv6 networks may take alot of time and use alot of system resources due to their large size.")
	}
	timeout := opts.cmd.Duration("timeout")
	ndpScanner := scanner.NewNDPScanner(&scanner.NDPScanOptions{
		Targets:   opts.targets,
		Source:    opts.source,
		Interface: *opts.iface,
	}).WithTimeout(timeout).WithVendorInfo()

	if opts.cmd.Bool("notify") {
		config, confErr := util.SetUpConfig()
		if confErr != nil {
			return confErr
		}
		notifierName := config.GetString("notifier.type")
		if notifierName == "" {
			return fmt.Errorf("no notifier type set in the config file")
		}
		notifierObj, err := notifier.NotifierByName(notifierName, config)
		if err != nil {
			return err
		}
		ndpScanner = ndpScanner.WithNotifier(notifierObj)
	}
	if opts.cmd.Bool("hostnames") {
		ndpScanner = ndpScanner.WithHostNames(nil, true)
	}
	err := ndpScanner.Scan()
	if err != nil {
		return err
	}
	var ndpResults scanner.NDPScanResults
	if results, ok := ndpScanner.Results().(scanner.NDPScanResults); ok {
		ndpResults = results
	} else {
		return fmt.Errorf("error getting ndp results")
	}
	var ndpStats scanner.NDPScanStats
	if stats, ok := ndpScanner.Stats().(scanner.NDPScanStats); ok {
		ndpStats = stats
	} else {
		return fmt.Errorf("error getting ndp stats")
	}
	displayNDPResults(&ndpResults, &ndpStats)

	if opts.cmd.Bool("notify") {
		err = ndpScanner.SendResultsViaNotifier()
		if err != nil {
			return err
		}
	}
	return nil
}
