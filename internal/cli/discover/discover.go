// Package discover is used to discover hosts on a network using ARP for IPv4 or ICMPv6 Neigbour Discovery for IPv6.
package discover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/kakeetopius/gscn/internal/util"
	"github.com/kakeetopius/gscn/pkg/scanner"
	"github.com/pterm/pterm"
	"github.com/urfave/cli/v3"
)

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

	targets := make([]netip.Prefix, 0)

	useIP6 := cmd.Bool("six")

	timeout := cmd.Duration("timeout")

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
			pterm.Info.Println("No targets Provided. Scanning for hosts on network: ", target.Masked())
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

	ifaceOpts := scanner.Interface{
		Interface: iface,
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

	doReverseLookup := cmd.Bool("hostnames")
	if useIP6 {
		if !targets[0].Addr().Is6() {
			return fmt.Errorf("the given IP address is not IPv6")
		}
		ndpScanner := scanner.NewNDPScanner(&scanner.NDPScanOptions{
			Targets:   targets,
			Source:    sourceAddr,
			Interface: ifaceOpts,
		}).WithTimeout(timeout).WithVendorInfo()

		if doReverseLookup {
			ndpScanner = ndpScanner.WithHostNames(nil, true)
		}
		err = ndpScanner.Scan()
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

	} else {
		if !targets[0].Addr().Is4() {
			return fmt.Errorf("arp can only be used with IPv4 addresses")
		}

		arpScanner := scanner.NewARPScanner(&scanner.ARPScanOptions{
			Targets:   targets,
			Source:    sourceAddr,
			Interface: ifaceOpts,
		}).WithTimeout(timeout).WithVendorInfo()
		if doReverseLookup {
			arpScanner = arpScanner.WithHostNames(nil, true)
		}
		err = arpScanner.Scan()
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
	}

	return nil
}
