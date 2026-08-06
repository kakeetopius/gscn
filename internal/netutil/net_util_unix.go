//go:build unix

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

	interfaces := make([]Interface, 0, len(ifaces))
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

		interfaces = append(interfaces, netIface)
	}

	r := realNetInterfaceProvider{
		interfaces: interfaces,
	}

	return &r, nil
}
