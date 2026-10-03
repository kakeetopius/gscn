//go:build linux

package routing

import (
	"net/netip"

	"github.com/jsimonetti/rtnetlink/rtnl"
	"github.com/kakeetopius/gscn/internal/netutil"
	"golang.org/x/sys/unix"
)

func getRoutingTable(ifaceProvider netutil.NetInterfaceProvider) (*RoutingTable, error) {
	rTable := new(RoutingTable)
	err := insertLoopbackRoutes(rTable, ifaceProvider)
	if err != nil {
		return nil, err
	}

	rt, err := rtnl.Dial(nil)
	if err != nil {
		return nil, err
	}

	routes, err := rt.Conn.Route.List()
	if err != nil {
		return nil, err
	}

	for _, route := range routes {
		if route.Table != unix.RT_TABLE_MAIN {
			continue
		}
		if route.Type != unix.RTN_UNICAST {
			continue
		}
		if route.Attributes.OutIface == 0 {
			continue
		}

		var prefix netip.Prefix
		var gateway netip.Addr
		var prefSrc netip.Addr

		if route.Attributes.Dst != nil {
			addr, ok := netip.AddrFromSlice(route.Attributes.Dst)
			if !ok {
				continue
			}
			prefix = netip.PrefixFrom(addr, int(route.DstLength))
		} else {
			// indicates the route is the default route 0.0.0.0/0 or ::/0
			prefix = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		}

		if route.Attributes.Gateway != nil {
			gw, ok := netip.AddrFromSlice(route.Attributes.Gateway)
			if !ok {
				continue
			}
			gateway = gw
		} else {
			// indicates the target ip is directly connected
			gateway = netip.IPv4Unspecified()
		}

		iface, err := ifaceProvider.InterfaceByIndex(int(route.Attributes.OutIface))
		if err != nil {
			return nil, err
		}

		if route.Attributes.Src != nil {
			src, ok := netip.AddrFromSlice(route.Attributes.Src)
			if !ok {
				continue
			}
			prefSrc = src
		} else {
			// if no src addr is given try to find on the interface on the same network as the gateway
			src, err := iface.AddrOnSameNetworkAs(gateway)
			if err != nil {
				// Fall back to the first interface ip.
				ifAddr, err := iface.FirstAddr(netutil.AddressFamilyOf(gateway))
				if err != nil {
					return nil, err
				}
				src = ifAddr.Addr()
			}

			prefSrc = src
		}

		rTable.insertRoute(Route{
			Network:   prefix,
			NextHop:   gateway,
			Metric:    route.Attributes.Priority,
			Interface: iface,
			SrcAddr:   prefSrc,
		})

	}

	return rTable, nil
}

func insertLoopbackRoutes(t *RoutingTable, ifaceProvider netutil.NetInterfaceProvider) error {
	lo, err := netutil.LoopbackInterface(ifaceProvider)
	if err != nil {
		return err
	}
	t.Insert(
		netip.MustParsePrefix("127.0.0.1/8"),
		[]Route{
			{
				Network:   netip.MustParsePrefix("127.0.0.1/8"),
				NextHop:   netip.IPv4Unspecified(),
				Interface: *lo,
			},
		},
	)

	t.Insert(
		netip.MustParsePrefix("::1/128"),
		[]Route{
			{
				Network:   netip.MustParsePrefix("::1/128"),
				NextHop:   netip.IPv6Unspecified(),
				Interface: *lo,
			},
		},
	)

	return nil
}
