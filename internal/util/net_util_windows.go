package util

import (
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

// go: build windows

type RealNetInterfaceProvider struct{}

func (RealNetInterfaceProvider) Interfaces() ([]Interface, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	ifaces := make([]Interface, 0, len(devs))
	for _, dev := range devs {
		ifaces = append(ifaces, Interface{
			Name: dev.Name,
			Interface: net.Interface{
				Name:  dev.Name,
				Flags: net.Flags(dev.Flags),
			},
			address: pcapInterfaceAddressestoIPNets(dev.Addresses),
		})
	}

	return ifaces, nil
}

func (RealNetInterfaceProvider) AddrsOf(iface *Interface) ([]net.Addr, error) {
	return iface.address, nil
}

func (RealNetInterfaceProvider) InterfaceByName(name string) (*Interface, error) {
	return nil, fmt.Errorf("not supported on windows")
}

func pcapInterfaceAddressestoIPNets(addrs []pcap.InterfaceAddress) []net.Addr {
	addresses := make([]net.Addr, 0, len(addrs))

	for _, addr := range addrs {
		addresses = append(addresses, &net.IPNet{
			IP:   addr.IP,
			Mask: addr.Netmask,
		})
	}

	return addresses
}

func VerifyInterface(interfaceProvider NetInterfaceProvider, iface *Interface) error {
	return nil
}
