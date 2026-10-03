// Package routing provides a very basic router to help determine where to send raw packets to.
package routing

import (
	"fmt"
	"net/netip"

	"github.com/gaissmai/bart"
	"github.com/kakeetopius/gscn/internal/netutil"
)

// Router performs route lookups for destination IP addresses.
type Router interface {
	// Lookup returns the route that should be used to reach the destination address.
	Lookup(dst netip.Addr) (Route, error)
}

// Route describes how to reach a destination network.
type Route struct {
	// Network is the destination network for this route.
	Network netip.Prefix

	// SrcAddr is the source IP address that should be used when sending packets via this route.
	SrcAddr netip.Addr

	// NextHop is the IP address of the next-hop gateway. For directly connected routes, it is the actual destination IP address.
	NextHop netip.Addr

	// Metric is the route's cost. Lower values indicate more preferred routes when multiple routes have the same prefix length.
	Metric uint32

	// Interface is the outgoing network interface for this route.
	Interface netutil.Interface

	// DirectlyConnected reports whether the destination network is directly connected to the outgoing interface.
	DirectlyConnected bool
}

type Routes []Route

type RoutingTable struct {
	bart.Fast[Routes]
}

// ErrRouteNotFound indicates that no route exists for the specified destination IP address.
type ErrRouteNotFound struct {
	// DstIP is the destination address for which no route was found.
	DstIP netip.Addr
}

func (r ErrRouteNotFound) Error() string {
	return fmt.Sprintf("route to %s not found", r.DstIP.String())
}
