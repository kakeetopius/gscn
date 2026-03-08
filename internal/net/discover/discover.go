// Package discover is used to discover hosts on a network using ARP for IPv4 or ICMPv6 Neigbour Discovery for IPv6.
package discover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/kakeetopius/gscn/internal/netutils"
	"github.com/pterm/pterm"
	"github.com/urfave/cli/v3"
)

type DiscoverOptions struct {
	Targets   []netip.Prefix
	Source    *netip.Addr
	Interface *netutils.IfaceOpts
	Timeout   int
}

type DiscoverResult struct {
	ipAddr   string
	macAddr  string
	hostName string
	vendor   string
}

var (
	packetsSent     = 0
	packetsReceived = 0
)

type RealNetInterfaceProvider struct{}

func (RealNetInterfaceProvider) Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}

func (RealNetInterfaceProvider) AddrsOf(iface *net.Interface) ([]net.Addr, error) {
	return iface.Addrs()
}

func RunDiscover(ctx context.Context, cmd *cli.Command) error {
	var opts DiscoverOptions
	var iface *net.Interface
	var err error
	targets := make([]netip.Prefix, 0)

	useIP6 := cmd.Bool("six")

	opts.Timeout = cmd.Int("timeout")

	if targetStr := cmd.String("target"); targetStr != "" {
		targets, err = netutils.DiscoverTargetsFromString(targetStr)
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
			target, err = netutils.GetFirstIfaceIPNet(netInterfaceProvider, iface, useIP6)
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
			iface, err = netutils.GetIfaceByIP(netInterfaceProvider, target.Addr())
			if err != nil {
				if errors.Is(err, netutils.ErrNoInterfaceConnectedToTarget) {
					continue
				}
				return err
			}
		}
	}

	if iface == nil {
		return fmt.Errorf("could not determine which interface to use. Use -i option to provide an interface or provide one target with an IP connected to one of the interface networks")
	} else if len(targets) == 0 {
		return fmt.Errorf("could not determine which targets to scan. Use the gscn discover --help for more information")
	}
	err = netutils.VerifyInterface(netInterfaceProvider, iface)
	if err != nil {
		return err
	}

	opts.Targets = targets
	ifaceOpts := netutils.IfaceOpts{
		Interface: iface,
	}
	opts.Interface = &ifaceOpts

	if source := cmd.String("source"); source != "" {
		source, parseerr := netip.ParseAddr(source)
		if parseerr != nil {
			return fmt.Errorf("error parsing source address :%v", parseerr)
		}
		opts.Source = &source
	} else {
		source, nerr := netutils.GetSourceIPFromInterface(netInterfaceProvider, iface, targets, useIP6)
		if nerr != nil {
			return err
		}
		opts.Source = source
	}

	var results []DiscoverResult
	if useIP6 {
		if !targets[0].Addr().Is6() {
			return fmt.Errorf("the given IP address is not IPv6")
		}
		results, err = runIPv6Disc(&opts)
	} else {
		if !targets[0].Addr().Is4() {
			return fmt.Errorf("arp can only be used with IPv4 addresses")
		}
		results, err = runArp(&opts)
	}
	if err != nil {
		return err
	}

	doReverseLookup := cmd.Bool("reverse")
	if doReverseLookup {
		doReverseLookup = true
		addHostNames(results, time.Duration(opts.Timeout))
	}
	addVendors(results)
	displayDiscoverResults(results, doReverseLookup)
	return err
}
