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
		addrs := pcapInterfaceAddressestoIPNets(dev.Addresses)
		netIface, err := netInterfaceFromAddrs(addrs)
		if err != nil {
			// skip those without mac addresses.
			continue
		}
		ifaces = append(ifaces, Interface{
			Name:      dev.Name,
			Interface: netIface,
			address:   addrs,
		})
	}

	return ifaces, nil
}

func (RealNetInterfaceProvider) AddrsOf(iface *Interface) ([]net.Addr, error) {
	return iface.address, nil
}

func (RealNetInterfaceProvider) InterfaceByName(name string) (*Interface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	pcapIface, err := pcapInterfaceFromAddrs(addrs)
	if err != nil {
		return nil, err
	}

	return &Interface{
		Name:      pcapIface.Name,
		Interface: *iface,
		address:   pcapInterfaceAddressestoIPNets(pcapIface.Addresses),
	}, nil
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

// netInterfaceFromAddrs attempts to find a net.interface based on the IP addresses the interface returned by pcap on Windows.
func netInterfaceFromAddrs(givenAddrs []net.Addr) (net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, err
	}
	for _, iface := range ifaces {
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			return net.Interface{}, err
		}
		for _, ifaceaddr := range ifaceAddrs {
			iaddr, ok := ifaceaddr.(*net.IPNet)
			if !ok {
				return net.Interface{}, fmt.Errorf("could not get net.Interface")
			}
			for _, givenAddr := range givenAddrs {
				addrGiven, ok := givenAddr.(*net.IPNet)
				if !ok {
					return net.Interface{}, fmt.Errorf("could not get net.Interface")
				}
				if addrGiven.IP.Equal(iaddr.IP) {
					return iface, nil
				}
			}
		}
	}
	return net.Interface{}, fmt.Errorf("could not get net.Interface")
}

func pcapInterfaceFromAddrs(givenAddrs []net.Addr) (pcap.Interface, error) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return pcap.Interface{}, err
	}
	for _, iface := range ifaces {
		ifaceAddrs := pcapInterfaceAddressestoIPNets(iface.Addresses)
		for _, ifaceaddr := range ifaceAddrs {
			iaddr, ok := ifaceaddr.(*net.IPNet)
			if !ok {
				return pcap.Interface{}, fmt.Errorf("could not pcap.Interface")
			}
			for _, givenAddr := range givenAddrs {
				addrGiven, ok := givenAddr.(*net.IPNet)
				if !ok {
					return pcap.Interface{}, fmt.Errorf("could not pcap.Interface")
				}
				if addrGiven.IP.Equal(iaddr.IP) {
					return iface, nil
				}
			}
		}
	}
	return pcap.Interface{}, fmt.Errorf("could not pcap.Interface")
}
