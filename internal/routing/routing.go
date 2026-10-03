package routing

import (
	"fmt"
	"net/netip"

	"github.com/kakeetopius/gscn/internal/netutil"
)

type router struct {
	v4Table       *RoutingTable
	v6Table       *RoutingTable
	ifaceProvider netutil.NetInterfaceProvider
}

func NewRouter(ifaceProvider netutil.NetInterfaceProvider) (Router, error) {
	v4table, v6table, err := getRoutingTables(ifaceProvider)
	if err != nil {
		return nil, err
	}
	return &router{
		v4Table:       v4table,
		v6Table:       v6table,
		ifaceProvider: ifaceProvider,
	}, nil
}

func (r *router) Lookup(dst netip.Addr) (Route, error) {
	switch {
	case dst.Is4():
		return r.lookupV4(dst)
	case dst.Is6():
		return r.lookupV6(dst)
	default:
		return Route{}, fmt.Errorf("invalid IP address: %v", dst)
	}
}

func (r *router) lookupV4(dst netip.Addr) (best Route, err error) {
	routes, found := r.v4Table.Lookup(dst)
	if !found || len(routes) == 0 {
		return Route{}, ErrRouteNotFound{DstIP: dst}
	}
	best = routes[0] // routes were sorted in ascending metric when inserting so first route has best metric

	if best.NextHop == netip.IPv4Unspecified() {
		// the route is for a directly connected network so the NextHop is dst itself.
		best.NextHop = dst
		best.DirectlyConnected = true
	}

	return best, nil
}

func (r *router) lookupV6(dst netip.Addr) (best Route, err error) {
	var expectedIfaceIndex *int

	if dst.Zone() != "" {
		iface, zerr := r.ifaceProvider.InterfaceByName(dst.Zone())
		if zerr != nil {
			return Route{}, zerr
		}
		expectedIfaceIndex = &iface.Index
	}

	routes, found := r.v6Table.Lookup(dst)
	if !found || len(routes) == 0 {
		return Route{}, ErrRouteNotFound{DstIP: dst}
	}

	defer func() {
		// make sure the nexthop is initialised well.
		if err == nil && best.NextHop == netip.IPv6Unspecified() {
			// the route is for a directly connected network so the NextHop is dst itself.
			best.NextHop = dst
			best.DirectlyConnected = true
		}
	}()

	if expectedIfaceIndex == nil {
		return routes[0], nil
	}

	routesWithExpectedIface := make(Routes, 0)
	for _, r := range routes {
		if r.Interface.Index != *expectedIfaceIndex {
			continue
		}
		routesWithExpectedIface = append(routesWithExpectedIface, r)
	}

	if len(routesWithExpectedIface) == 0 {
		return Route{}, ErrRouteNotFound{DstIP: dst}
	}

	best = minMetric(routesWithExpectedIface)

	return best, nil
}

func minMetric(routes Routes) Route {
	if len(routes) == 0 {
		return Route{}
	}

	min := routes[0]

	for _, r := range routes {
		if r.Metric < min.Metric {
			min = r
		}
	}

	return min
}
