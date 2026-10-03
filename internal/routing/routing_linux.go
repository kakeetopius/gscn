//go:build linux

package routing

import (
	"net/netip"

	"github.com/jsimonetti/rtnetlink/rtnl"
	"github.com/kakeetopius/gscn/internal/netutil"
	"golang.org/x/sys/unix"
)

func getRoutingTables(ifaceProvider netutil.NetInterfaceProvider) (*RoutingTable, *RoutingTable, error) {
	v4Table := new(RoutingTable)
	v6Table := new(RoutingTable)

	err := insertv4LoopbackRoute(v4Table, ifaceProvider)
	if err != nil {
		return nil, nil, err
	}
	err = insertv6LoopbackRoute(v6Table, ifaceProvider)
	if err != nil {
		return nil, nil, err
	}

	rt, err := rtnl.Dial(nil)
	if err != nil {
		return nil, nil, err
	}

	routes, err := rt.Conn.Route.List()
	if err != nil {
		return nil, nil, err
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
			if route.Family == unix.AF_INET {
				// indicates the route is the default route 0.0.0.0/0 or ::/0
				prefix = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
			} else {
				prefix = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
			}
		}

		if route.Attributes.Gateway != nil {
			gw, ok := netip.AddrFromSlice(route.Attributes.Gateway)
			if !ok {
				continue
			}
			gateway = gw
		} else {
			if route.Family == unix.AF_INET {
				// indicates the target ip is directly connected
				gateway = netip.IPv4Unspecified()
			} else {
				gateway = netip.IPv6Unspecified()
			}
		}

		iface, err := ifaceProvider.InterfaceByIndex(int(route.Attributes.OutIface))
		if err != nil {
			return nil, nil, err
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
				ifAddr, err := iface.FirstAddr(netutil.AddressFamily(route.Family))
				if err != nil {
					return nil, nil, err
				}
				src = ifAddr.Addr()
			}

			prefSrc = src
		}

		r := Route{
			Network:   prefix,
			NextHop:   gateway,
			Metric:    route.Attributes.Priority,
			Interface: iface,
			SrcAddr:   prefSrc,
		}

		switch route.Family {
		case unix.AF_INET:
			v4Table.insertRoute(r)
		case unix.AF_INET6:
			v6Table.insertRoute(r)
		}

	}

	return v4Table, v6Table, nil
}

func insertv4LoopbackRoute(t *RoutingTable, ifaceProvider netutil.NetInterfaceProvider) error {
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

	return nil
}

func insertv6LoopbackRoute(t *RoutingTable, ifaceProvider netutil.NetInterfaceProvider) error {
	lo, err := netutil.LoopbackInterface(ifaceProvider)
	if err != nil {
		return err
	}
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
