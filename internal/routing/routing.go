package routing

import (
	"net/netip"
	"sync"

	"github.com/kakeetopius/gscn/internal/netutil"
)

type generalRouter struct {
	table         routingTable
	ifaceProvider netutil.NetInterfaceProvider
	cache         map[netip.Addr]Route
	cacheMu       sync.Mutex
}

func NewRouter(ifaceProvider netutil.NetInterfaceProvider) (Router, error) {
	rt, err := getRoutingTable()
	if err != nil {
		return nil, err
	}
	return &generalRouter{
		ifaceProvider: ifaceProvider,
		table:         rt,
		cache:         make(map[netip.Addr]Route),
	}, nil
}

func (r *generalRouter) Lookup(dst netip.Addr) (Route, error) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	if route, found := r.cache[dst]; found {
		return route, nil
	}
	var best *Route

	var expectedIfaceIndex *int
	if dst.Zone() != "" {
		iface, err := r.ifaceProvider.InterfaceByName(dst.Zone())
		if err != nil {
			return Route{}, err
		}
		expectedIfaceIndex = &iface.Index

		dst = dst.WithZone("") // strip the zone
	}

	for _, route := range r.table {
		if !route.Network.Contains(dst) {
			// If the destination address is not within this route's network.
			continue
		}

		if best != nil {
			if hasLongerPrefix(best.Network, route.Network) {
				// if current best route is more specific than this route
				continue
			}
			if haveEqualPrefix(route.Network, best.Network) && route.Metric >= best.Metric {
				// Same prefix length, but this route has a higher or equal metric.
				continue
			}
		}

		if expectedIfaceIndex != nil && route.IfIndex != *expectedIfaceIndex {
			// if the ipv6 zone (network interface) given differs from the current route's interface.
			continue
		}

		iface, err := r.ifaceProvider.InterfaceByIndex(route.IfIndex)
		if err != nil {
			return Route{}, err
		}
		best = &Route{
			Network:   route.Network,
			NextHop:   route.Gateway,
			Interface: iface,
			Metric:    route.Metric,
		}

		if route.Gateway == netip.IPv4Unspecified() || route.Gateway == netip.IPv6Unspecified() {
			// the route is for a directly connected network.
			best.NextHop = dst
			best.DirectlyConnected = true
		}

		srcAddr := route.PrefSrc
		if srcAddr == nil {
			src, err := best.Interface.AddrOnSameNetworkAs(best.NextHop)
			if err != nil {
				// Fall back to the first interface ip.
				ifAddr, err := best.Interface.FirstAddr(netutil.AddressFamilyOf(dst))
				if err != nil {
					return Route{}, err
				}
				src = ifAddr.Addr()
			}

			srcAddr = &src
		}

		best.SrcAddr = *srcAddr
	}

	if best == nil {
		return Route{}, ErrRouteNotFound{DstIP: dst}
	}

	r.cache[dst] = *best
	return *best, nil
}

func hasLongerPrefix(a, b netip.Prefix) bool {
	return a.Bits() > b.Bits()
}

func haveEqualPrefix(a, b netip.Prefix) bool {
	return a.Bits() == b.Bits()
}
