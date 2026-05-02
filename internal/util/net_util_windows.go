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
	pcapIface, err := pcapInterfaceFromAddrs(addrs) // it is needed coz the pcap.Interface has the special Name required for opening a pcap handle for sending packets.
	if err != nil {
		return nil, err
	}

	return &Interface{
		Name:      pcapIface.Name,
		Interface: *iface,
		address:   pcapInterfaceAddressestoIPNets(pcapIface.Addresses),
	}, nil
}

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

// When sending packets on windows, pcap is used instead of the raw sockets that are available on linux only.
// The pcap library on windows requires some special names for the interface which can only be gotten via the pcap.FindAllDevs() function which returns pcap.Interface structs
// but these structs returned by pcap.FindAllDevs() do not contain all information for example the interfaces' hardware address, index etc.
// So these functions help to connect the two: pcap.Interface and net.Interface via the only common data that can be got from both -> their IP addresses.

// pcapInterfaceAddressestoIPNets converts pcap.InterfaceAddress structs to net.Addr (net.IPNet specifically)
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

// netInterfaceFromAddrs attempts to find a net.interface that has one of the IP addresses given
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

// pcapInterfaceFromAddrs attempts to find a pcap.Interface that has one of the IP addresses given
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
