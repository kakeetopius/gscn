// Package discover is used to discover hosts on a network using ARP for IPv4 or ICMPv6 Neigbour Discovery for IPv6.
package discover

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/kakeetopius/gscn/pkg/scanner"
	"github.com/pterm/pterm"
	"github.com/spf13/viper"
)

type DiscoverOpts struct {
	Config           *viper.Viper
	TargetsString    string
	InterfaceString  string
	SourceAddrString string
	Timeout          time.Duration
	UseIP6           bool
	Notify           bool
	ResolveHostnames bool
	FromCache        bool
	ForceIP6Scan     bool

	targets    []netip.Prefix
	iface      *net.Interface
	sourceAddr netip.Addr
}

type RealNetInterfaceProvider struct{}

func (RealNetInterfaceProvider) Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}

func (RealNetInterfaceProvider) AddrsOf(iface *net.Interface) ([]net.Addr, error) {
	return iface.Addrs()
}

func RunDiscover(opts DiscoverOpts) error {
	var iface *net.Interface
	var err error

	useIP6 := opts.UseIP6

	targets := make([]netip.Prefix, 0)
	if targetStr := opts.TargetsString; targetStr != "" {
		targets, err = scanner.TargetsFromString(targetStr)
		if err != nil {
			return err
		}
	}

	netInterfaceProvider := RealNetInterfaceProvider{}

	if ifaceName := opts.InterfaceString; ifaceName != "" {
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
		// if no interface given but we have some IPs then find an interface on the same network as one of the targets.
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
	if source := opts.SourceAddrString; source != "" {
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

	opts.targets = targets
	opts.iface = iface
	opts.sourceAddr = sourceAddr

	if useIP6 {
		err = runIP6Discovery(&opts)
	} else {
		err = runIP4Discovery(&opts)
	}

	return err
}

func runIP4Discovery(opts *DiscoverOpts) error {
	for _, target := range opts.targets {
		if !target.Addr().Is4() {
			return fmt.Errorf("%v is not an IPv4 address", target)
		}
	}
	timeout := opts.Timeout
	arpScanner := scanner.NewARPScanner(&scanner.ARPScanOptions{
		Targets:         opts.targets,
		Source:          opts.sourceAddr,
		Interface:       *opts.iface,
		ResponseTimeout: timeout,
		WithVendorInfo:  true,
	})

	if opts.Notify {
		config := opts.Config
		notifierName := config.GetString("notifier.type")
		if notifierName == "" {
			return fmt.Errorf("no notifier type set in the config file")
		}
		notifierObj, err := notifier.NotifierByName(notifierName, config)
		if err != nil {
			return err
		}
		arpScanner.MessageNotifier = notifierObj
	}
	if opts.ResolveHostnames {
		arpScanner.AddUnknownHostNames = true
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
	if opts.Notify {
		err = arpScanner.SendResultsViaNotifier()
		if err != nil {
			return err
		}
	}
	return nil
}

func runIP6Discovery(opts *DiscoverOpts) error {
	useCache := opts.FromCache
	forceScan := opts.ForceIP6Scan
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
	timeout := opts.Timeout
	ndpScanner := scanner.NewNDPScanner(&scanner.NDPScanOptions{
		Targets:         opts.targets,
		Source:          opts.sourceAddr,
		Interface:       *opts.iface,
		ResponseTimeout: timeout,
		WithVendorInfo:  true,
	})

	if opts.Notify {
		config := opts.Config
		notifierName := config.GetString("notifier.type")
		if notifierName == "" {
			return fmt.Errorf("no notifier type set in the config file")
		}
		notifierObj, err := notifier.NotifierByName(notifierName, config)
		if err != nil {
			return err
		}
		ndpScanner.MessageNotifier = notifierObj
	}
	if opts.ResolveHostnames {
		ndpScanner.AddUnknownHostNames = true
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

	if opts.Notify {
		err = ndpScanner.SendResultsViaNotifier()
		if err != nil {
			return err
		}
	}
	return nil
}
