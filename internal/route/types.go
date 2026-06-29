// Package route helps to find which interface to direct packets to.
package route

import (
	"net/netip"

	"github.com/kakeetopius/gscn/internal/netutil"
)

type Router interface {
	Lookup(dst netip.Addr) (*netutil.Interface, netip.Addr, error)
}
