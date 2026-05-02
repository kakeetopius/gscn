package util

import (
	"fmt"
	"net"
)

// go: build linux

type RealNetInterfaceProvider struct{}

func (RealNetInterfaceProvider) Interfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	addresses := make([]Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		addresses = append(addresses, Interface{
			Name:      iface.Name,
			Interface: iface,
		})
	}

	return addresses, nil
}

func (RealNetInterfaceProvider) AddrsOf(iface *Interface) ([]net.Addr, error) {
	return iface.Addrs()
}

func (RealNetInterfaceProvider) InterfaceByName(name string) (*Interface, error) {
	netIface, neterr := net.InterfaceByName(name)
	if neterr != nil {
		return nil, neterr
	}
	return &Interface{
		Name:      netIface.Name,
		Interface: *netIface,
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

	ifaceAddrs, err := interfaceProvider.AddrsOf(iface)
	if err != nil {
		return err
	}
	if len(ifaceAddrs) < 1 {
		return fmt.Errorf("interface %v has no IP addresses", iface.Name)
	}

	return nil
}
