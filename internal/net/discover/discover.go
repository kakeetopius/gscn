// Package discover is used to discover hosts on a network using ARP for IPv4 or ICMPv6 Neigbour Discovery for IPv6.
package discover

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/kakeetopius/gscn/internal/netutils"
	"github.com/urfave/cli/v3"
)

type DiscoverOptions struct {
	Target    *netip.Prefix
	Interface *netutils.IfaceDetails
	Timeout   int
}

func RunDiscover(ctx context.Context, cmd *cli.Command) error {
	var opts DiscoverOptions
	var target *netip.Prefix
	var iface *net.Interface
	ifaceGiven := cmd.String("iface") != ""
	useIP6 := cmd.Bool("six")

	if hostIP := cmd.String("host"); hostIP != "" {
		addr, err := netip.ParsePrefix(fmt.Sprintf("%v/%v", hostIP, 32))
		if err != nil {
			return err
		}
		target = &addr
		if !ifaceGiven {
			iface, err = netutils.GetIfaceByIP(target.Addr())
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
			iface, err = netutils.GetIfaceByIP(target.Addr())
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
			target, err = netutils.GetFirstIfaceIPNet(iface, useIP6)
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
	opts.Interface, err = netutils.VerifyandGetIfaceDetails(iface, target, useIP6)
	if err != nil {
		return err
	}
	opts.Target = target
	opts.Timeout = cmd.Int("timeout")

	if useIP6 {
		if !target.Addr().Is6() {
			return fmt.Errorf("the given IP address is not IPv6")
		}
		err = runIPv6Disc(&opts, cmd)
	} else {
		if !target.Addr().Is4() {
			return fmt.Errorf("arp can only be used with IPv4 addresses")
		}
		err = runArp(&opts, cmd)
	}
	return err
}
