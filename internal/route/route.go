package route

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/kakeetopius/gscn/internal/netutil"
)

func NewRouter() (Router, error) {
	return generalRouter{
		ifaceProvider: &netutil.RealNetInterfaceProvider{},
	}, nil
}

type generalRouter struct {
	ifaceProvider netutil.NetInterfaceProvider
}

func (r generalRouter) Lookup(dst netip.Addr) (netutil.Interface, netip.Addr, error) {
	proto := "udp4"
	if dst.Is6() {
		proto = "udp6"
	}

	addrPort := netip.AddrPortFrom(dst, 69)

	conn, err := net.Dial(proto, addrPort.String())
	if err != nil {
		return netutil.Interface{}, netip.Addr{}, err
	}

	srcIP, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netutil.Interface{}, netip.Addr{}, fmt.Errorf("could not get route for %s", dst.String())
	}

	srcAddr, ok := netip.AddrFromSlice(srcIP.IP)
	if !ok {
		return netutil.Interface{}, netip.Addr{}, fmt.Errorf("could not get route for: %s", dst.String())
	}

	iface, err := netutil.GetIfaceByIP(r.ifaceProvider, srcAddr)
	if err != nil {
		return netutil.Interface{}, netip.Addr{}, err
	}

	return *iface, srcAddr, nil
}
