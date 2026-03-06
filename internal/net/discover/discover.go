// Package discover is used to discover hosts on a network using ARP for IPv4 or ICMPv6 Neigbour Discovery for IPv6.
package discover

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/kakeetopius/gscn/internal/netutils"
	"github.com/urfave/cli/v3"
)

type DiscoverOptions struct {
	Target    *netip.Prefix
	Source    *netip.Addr
	Interface *netutils.IfaceDetails
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
	var target *netip.Prefix
	var iface *net.Interface
	ifaceGiven := cmd.String("iface") != ""
	useIP6 := cmd.Bool("six")

	netInterfaceProvider := RealNetInterfaceProvider{}

	if hostIP := cmd.String("host"); hostIP != "" {
		var ipwithMask string
		if useIP6 {
			ipwithMask = fmt.Sprintf("%v/%v", hostIP, 64)
		} else {
			ipwithMask = fmt.Sprintf("%v/%v", hostIP, 32)
		}
		addr, err := netip.ParsePrefix(ipwithMask)
		if err != nil {
			return err
		}
		target = &addr
		if !ifaceGiven {
			iface, err = netutils.GetIfaceByIP(netInterfaceProvider, target.Addr())
			if err != nil {
				return err
			}
		}
	} else if netIP := cmd.String("network"); netIP != "" {
		net, err := netip.ParsePrefix(netIP)
		if err != nil {
			return err
		}
		target = &net
		if !ifaceGiven {
			iface, err = netutils.GetIfaceByIP(netInterfaceProvider, target.Addr())
			if err != nil {
				return err
			}
		}
	}

	var err error
	if ifaceName := cmd.String("iface"); ifaceName != "" {
		iface, err = net.InterfaceByName(ifaceName)
		if err != nil {
			return err
		}
		if target == nil {
			target, err = netutils.GetFirstIfaceIPNet(netInterfaceProvider, iface, useIP6)
			if err != nil {
				return err
			}
		}
	}

	if iface == nil {
		return fmt.Errorf("could not determine which interface to use. Use the -n or -H or -i options")
	} else if target == nil {
		return fmt.Errorf("could not determine which address to use. Use the -n or -H or -i options")
	}
	opts.Interface, err = netutils.VerifyandGetIfaceDetails(netInterfaceProvider, iface, target, useIP6)
	if err != nil {
		return err
	}
	opts.Target = target
	opts.Timeout = cmd.Int("timeout")

	if source := cmd.String("source"); source != "" {
		source, parseerr := netip.ParseAddr(source)
		if parseerr != nil {
			return parseerr
		}
		opts.Source = &source
	} else {
		opts.Source = &opts.Interface.IfaceIP
	}

	var results []DiscoverResult
	if useIP6 {
		if !target.Addr().Is6() {
			return fmt.Errorf("the given IP address is not IPv6")
		}
		results, err = runIPv6Disc(&opts)
	} else {
		if !target.Addr().Is4() {
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
