//go:build unix

package netutil

import (
	"net"
	"net/netip"
)

type RealNetInterfaceProvider struct {
	interfaces    []Interface
	isInitialised bool
}

func (r *RealNetInterfaceProvider) Interfaces() ([]Interface, error) {
	if r.isInitialised {
		return r.interfaces, nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	interfaces := make([]Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		prefixes, err := AddrSliceToPrefixSlice(addrs)
		if err != nil {
			return nil, err
		}
		interfaces = append(interfaces, Interface{
			PcapName:  iface.Name,
			Interface: iface,
			address:   prefixes,
		})
	}

	r.interfaces = interfaces
	r.isInitialised = true
	return interfaces, nil
}

func (RealNetInterfaceProvider) AddrsOf(iface *Interface) []netip.Prefix {
	return iface.address
}

func (RealNetInterfaceProvider) InterfaceByName(name string) (*Interface, error) {
	netIface, neterr := net.InterfaceByName(name)
	if neterr != nil {
		return nil, neterr
	}
	addrs, err := netIface.Addrs()
	if err != nil {
		return nil, err
	}
	prefixes, err := AddrSliceToPrefixSlice(addrs)
	if err != nil {
		return nil, err
	}
	return &Interface{
		PcapName:  netIface.Name,
		Interface: *netIface,
		address:   prefixes,
	}, nil
}
