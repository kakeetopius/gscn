//go:build linux

package routing

import (
	"net/netip"

	"github.com/jsimonetti/rtnetlink/rtnl"
	"golang.org/x/sys/unix"
)

func getRoutingTable() (routingTable, error) {
	rTable := make(routingTable, 0, 5)
	rTable = appendLoopbackRoutes(rTable)

	rt, err := rtnl.Dial(nil)
	if err != nil {
		return nil, err
	}

	routes, err := rt.Conn.Route.List()
	if err != nil {
		return nil, err
	}

	for _, route := range routes {
		var prefix netip.Prefix
		var gateway netip.Addr
		if route.Table != unix.RT_TABLE_MAIN {
			continue
		}
		if route.Type != unix.RTN_UNICAST {
			continue
		}
		if route.Attributes.OutIface == 0 {
			continue
		}

		if route.Attributes.Dst == nil {
			// indicates the route is the default route 0.0.0.0/0 or ::/0
			prefix = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		} else {
			addr, ok := netip.AddrFromSlice(route.Attributes.Dst)
			if !ok {
				continue
			}
			prefix = netip.PrefixFrom(addr, int(route.DstLength))
		}

		if route.Attributes.Gateway == nil {
			// indicates the target ip is directly connected
			gateway = netip.IPv4Unspecified()
		} else {
			gw, ok := netip.AddrFromSlice(route.Attributes.Gateway)
			if !ok {
				continue
			}
			gateway = gw
		}

		var prefSrc *netip.Addr
		if route.Attributes.Src != nil {
			src, ok := netip.AddrFromSlice(route.Attributes.Src)
			if !ok {
				continue
			}
			prefSrc = &src
		}

		rTable = append(rTable, routingTableEntry{
			Network: prefix,
			Gateway: gateway,
			Metric:  route.Attributes.Priority,
			IfIndex: int(route.Attributes.OutIface),
			PrefSrc: prefSrc,
		})
	}

	return rTable, nil
}

func appendLoopbackRoutes(r routingTable) routingTable {
	lbIP4 := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	lb6Addr := [16]byte{}
	lb6Addr[15] = 1
	lbIP6 := netip.AddrFrom16(lb6Addr)

	r = append(r, routingTableEntry{
		Network: netip.PrefixFrom(lbIP4, 8),
		Gateway: netip.IPv4Unspecified(),
		IfIndex: 1,
	})

	r = append(r, routingTableEntry{
		Network: netip.PrefixFrom(lbIP6, 128),
		Gateway: netip.IPv6Unspecified(),
		IfIndex: 1,
	})

	return r
}
