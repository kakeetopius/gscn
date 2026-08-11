//go:build !windows

package netutil

import (
	"net"
	"net/netip"
)

func InterfaceProvider() (*realNetInterfaceProvider, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	r := realNetInterfaceProvider{
		ifaceIndexIdx: make(map[int]int, len(ifaces)),
		ifaceNameIdx:  make(map[string]int, len(ifaces)),
		interfaces:    make([]Interface, 0, len(ifaces)),
	}

	var ifaceSliceCurrentIdx int
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		netIface := Interface{
			PcapName:  iface.Name,
			Interface: iface,
		}
		netIface.allAddresses = make([]netip.Prefix, 0, len(addrs))
		netIface.AppendNetAddr(addrs...)

		linktype, err := GetLinktypeOf(netIface.PcapName)
		if err != nil {
			return nil, err
		}
		netIface.LinkType = linktype

		r.interfaces = append(r.interfaces, netIface)
		r.ifaceIndexIdx[netIface.Index] = ifaceSliceCurrentIdx
		r.ifaceNameIdx[netIface.Name] = ifaceSliceCurrentIdx

		ifaceSliceCurrentIdx++
	}

	return &r, nil
}
