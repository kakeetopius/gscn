package util

import (
	"fmt"
	"net"
	"net/netip"
)

// go: build linux

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
			Name:      iface.Name,
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
		Name:      netIface.Name,
		Interface: *netIface,
		address:   prefixes,
	}, nil
}

// VerifyInterface validates whether iface is suitable for scanning operations.
//
// The interface must not be loopback, must be administratively up, must be
// running, and must have at least one assigned address as reported by
// interfaceProvider. It returns an error describing the first failed check.
func VerifyInterface(interfaceProvider NetInterfaceProvider, iface *Interface) error {
	if iface.Flags&net.FlagLoopback != 0 {
		return fmt.Errorf("cannot scan on a loopback interface")
	} else if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %v is administratively down", iface.Name)
	} else if iface.Flags&net.FlagRunning == 0 {
		return fmt.Errorf("interface %v is not running", iface.Name)
	}

	ifaceAddrs := interfaceProvider.AddrsOf(iface)
	if len(ifaceAddrs) < 1 {
		return fmt.Errorf("interface %v has no IP addresses", iface.Name)
	}

	return nil
}
