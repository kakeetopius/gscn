// Package resolve is used to resolve network addresses to their mac address
package resolve

import (
	"fmt"
	"net/netip"

	"github.com/kakeetopius/gscn/internal/netutil"
)

type Resolver interface {
	Resolve(netip.Addr) (netutil.MAC, error)
}

type ErrMacNotFound struct {
	// DstIP is the destination address for which the mac address was not found.
	DstIP netip.Addr
}

func (r ErrMacNotFound) Error() string {
	return fmt.Sprintf("mac address for %s not found", r.DstIP.String())
}
