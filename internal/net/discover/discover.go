// Package discover is used to discover hosts on a network using ARP for IPv4 or ICMPv6 Neigbour Discovery for IPv6.
package discover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/kakeetopius/gscn/internal/util"
	"github.com/pterm/pterm"
	"github.com/urfave/cli/v3"
)

type DiscoverOptions struct {
	Targets   []netip.Prefix
	Source    *netip.Addr
	Interface *util.IfaceOpts
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
		targets, err = discoverTargetsFromString(targetStr)
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

	opts.Targets = targets
	ifaceOpts := util.IfaceOpts{
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
		source, nerr := util.GetSourceIPFromInterface(netInterfaceProvider, iface, targets, useIP6)
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

func discoverTargetsFromString(s string) ([]netip.Prefix, error) {
	// Example: 10.1.1.1/24,10.1.1.1,10.1.1.1-2
	commaSeparatedTargets := strings.Split(s, ",")
	targets := make([]netip.Prefix, 0, 5)

	for _, targetString := range commaSeparatedTargets {
		if strings.ContainsRune(targetString, '/') {
			addr, err := netip.ParsePrefix(targetString)
			if err != nil {
				return nil, fmt.Errorf("error parsing target %v -> %v", targetString, err)
			}
			targets = append(targets, addr)
		} else if strings.ContainsRune(targetString, '-') {
			IPRange, err := util.ParseIPRange(targetString)
			if err != nil {
				return nil, err
			}
			targets = append(targets, IPRange...)
		} else {
			targetStr := fmt.Sprintf("%v/%v", targetString, 32)
			addr, err := netip.ParsePrefix(targetStr)
			if err != nil {
				return nil, fmt.Errorf("error parsing target %v -> %v", targetString, err)
			}
			targets = append(targets, addr)
		}
	}

	return util.Unique(targets), nil
}
