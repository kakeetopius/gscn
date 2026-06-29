//go:build linux

package route

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/google/gopacket/routing"
	"github.com/kakeetopius/gscn/internal/netutil"
)

type LinuxRouter struct {
	router routing.Router
}

func (r *LinuxRouter) Lookup(dst netip.Addr) (*netutil.Interface, netip.Addr, error) {
	iface, _, src, err := r.router.Route(net.IP(dst.AsSlice()))
	if err != nil {
		return nil, netip.Addr{}, err
	}

	srcAddr, ok := netip.AddrFromSlice(src)
	if !ok {
		return nil, netip.Addr{}, fmt.Errorf("could not get route for: %s", dst.String())
	}

	return &netutil.Interface{
		PcapName:  iface.Name,
		Interface: *iface,
	}, srcAddr, nil
}

func NewRouter() (Router, error) {
	router, err := routing.New()
	if err != nil {
		return nil, err
	}
	return &LinuxRouter{
		router: router,
	}, nil
}
