package routing

import (
	"net/netip"
	"slices"

	"github.com/kakeetopius/gscn/internal/netutil"
)

type router struct {
	table         *RoutingTable
	ifaceProvider netutil.NetInterfaceProvider
}

func NewRouter(ifaceProvider netutil.NetInterfaceProvider) (Router, error) {
	rt, err := getRoutingTable(ifaceProvider)
	if err != nil {
		return nil, err
	}
	return &router{
		table:         rt,
		ifaceProvider: ifaceProvider,
	}, nil
}

func (r *router) Lookup(dst netip.Addr) (Route, error) {
	best, err := r.getBestRouteTo(dst)
	if err != nil {
		return Route{}, err
	}

	if best.NextHop == netip.IPv4Unspecified() || best.NextHop == netip.IPv6Unspecified() {
		// the route is for a directly connected network so the NextHop is dst itself.
		best.NextHop = dst
		best.DirectlyConnected = true
	}

	return best, nil
}

func (t *RoutingTable) insertRoute(r Route) {
	if routes, found := t.Get(r.Network); found {
		routes = append(routes, r)

		slices.SortFunc(routes, func(a, b Route) int {
			return int(a.Metric) - int(b.Metric)
		})

		t.Insert(r.Network, routes)
		return
	}

	t.Insert(r.Network, Routes{r})
}

func (r *router) getBestRouteTo(dst netip.Addr) (Route, error) {
	var expectedIfaceIndex *int
	if dst.Zone() != "" {
		iface, err := r.ifaceProvider.InterfaceByName(dst.Zone())
		if err != nil {
			return Route{}, err
		}
		expectedIfaceIndex = &iface.Index

		dst = dst.WithZone("") // strip the zone
	}

	routes, found := r.table.Lookup(dst)
	if !found || len(routes) == 0 {
		return Route{}, ErrRouteNotFound{DstIP: dst}
	}

	if expectedIfaceIndex == nil {
		return routes[0], nil // routes were sorted in ascending metric when inserting so first route has best metric
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

	return minMetric(routesWithExpectedIface), nil
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
