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
		netIface := Interface{
			PcapName:  iface.Name,
			Interface: iface,
			addresses: prefixes,
		}
		linktype, err := GetLinktypeOf(netIface.PcapName)
		if err != nil {
			return nil, err
		}
		netIface.LinkType = linktype

		interfaces = append(interfaces, netIface)
	}

	r.interfaces = interfaces
	r.isInitialised = true
	return interfaces, nil
}

func (*RealNetInterfaceProvider) AddrsOf(iface *Interface) []netip.Prefix {
	return iface.addresses
}

func (*RealNetInterfaceProvider) InterfaceByName(name string) (*Interface, error) {
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
	linkType, err := GetLinktypeOf(netIface.Name)
	if err != nil {
		return nil, err
	}

	return &Interface{
		PcapName:  netIface.Name,
		Interface: *netIface,
		addresses: prefixes,
		LinkType:  linkType,
	}, nil
}

func (*RealNetInterfaceProvider) InterfaceByIndex(index int) (*Interface, error) {
	netIface, neterr := net.InterfaceByIndex(index)
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
	linkType, err := GetLinktypeOf(netIface.Name)
	if err != nil {
		return nil, err
	}
	return &Interface{
		PcapName:  netIface.Name,
		Interface: *netIface,
		addresses: prefixes,
		LinkType:  linkType,
	}, nil
}
