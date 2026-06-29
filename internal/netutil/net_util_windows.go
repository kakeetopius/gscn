//go:build windows

package netutil

import (
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/google/gopacket/pcap"
)

// When sending packets on windows, pcap is used instead of the raw sockets that are available on linux only.
// The pcap library on windows requires some special names for the interface which can only be gotten via the pcap.FindAllDevs() function which returns pcap.Interface structs
// but these structs returned by pcap.FindAllDevs() do not contain all information for example the interfaces' hardware address, index etc.
// So these functions help to connect the two: pcap.Interface and net.Interface via the only common data that can be got from both -> their IP addresses.
// All that is needed from pcap.Interface struct is the Name field which is then assigned to the Interface.PcapName field.

type RealNetInterfaceProvider struct {
	interfaces    []Interface
	isInitialised bool
}

func (r *RealNetInterfaceProvider) Interfaces() ([]Interface, error) {
	if r.isInitialised {
		return r.interfaces, nil
	}
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	ifaces := make([]Interface, 0, len(devs))
	for _, dev := range devs {
		// first convert []pcap.InterfaceAddress to []netip.Prefix
		addrs := pcapInterfaceAddressSliceToPrefixSlice(dev.Addresses)

		// get a net.Interface using the addresses returned by pcap
		netIface, err := netInterfaceFromAddrs(addrs)
		if err != nil {
			continue
		}
		ifaces = append(ifaces, Interface{
			PcapName:  dev.Name,
			Interface: netIface,
			address:   addrs,
		})
	}

	r.interfaces = ifaces
	r.isInitialised = true
	return ifaces, nil
}

func (*RealNetInterfaceProvider) AddrsOf(iface *Interface) []netip.Prefix {
	return iface.address
}

func (*RealNetInterfaceProvider) InterfaceByName(name string) (*Interface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	// convert from a []net.Addr to a []netip.Prefix
	prefixAddrs, err := AddrSliceToPrefixSlice(addrs)
	if err != nil {
		return nil, err
	}

	pcapIface, err := pcapInterfaceFromAddrs(prefixAddrs) // it is needed coz the pcap.Interface has the special Name required for opening a pcap handle for sending packets.
	if err != nil {
		return nil, err
	}

	return &Interface{
		PcapName:  pcapIface.Name,
		Interface: *iface,
		address:   prefixAddrs,
	}, nil
}

// pcapInterfaceAddressSliceToPrefixSlice converts a slice of pcap.InterfaceAddress to netip.Prefix.
// It skips any addresses that fail conversion and returns the successfully converted prefixes.
func pcapInterfaceAddressSliceToPrefixSlice(addrs []pcap.InterfaceAddress) []netip.Prefix {
	addresses := make([]netip.Prefix, 0, len(addrs))

	for _, addr := range addrs {
		prefix, err := IPNetToPrefix(&net.IPNet{
			IP:   addr.IP,
			Mask: addr.Netmask,
		})
		if err != nil {
			continue
		}
		addresses = append(addresses, prefix)
	}

	return addresses
}

// netInterfaceFromAddrs finds and returns a net.Interface that contains any of the given network addresses.
// It iterates through all available network interfaces, comparing their addresses with the provided addresses.
// Returns the first matching interface, or an error if no match is found or if interface enumeration fails.
func netInterfaceFromAddrs(givenAddrs []netip.Prefix) (net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, err
	}
	for _, iface := range ifaces {
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			return net.Interface{}, err
		}
		ifacePrefixes, err := AddrSliceToPrefixSlice(ifaceAddrs)
		if err != nil {
			return net.Interface{}, err
		}
		for _, ifaceaddr := range ifacePrefixes {
			if slices.Contains(givenAddrs, ifaceaddr) {
				return iface, nil
			}
		}
	}
	return net.Interface{}, fmt.Errorf("could not find matching net.Interface")
}

// pcapInterfaceFromAddrs finds a pcap.Interface that contains any of the given addresses.
// It returns the first matching interface or an error if no match is found.
func pcapInterfaceFromAddrs(givenAddrs []netip.Prefix) (pcap.Interface, error) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return pcap.Interface{}, err
	}
	for _, iface := range ifaces {
		ifaceAddrs := pcapInterfaceAddressSliceToPrefixSlice(iface.Addresses)
		for _, ifaceaddr := range ifaceAddrs {
			if slices.Contains(givenAddrs, ifaceaddr) {
				return iface, nil
			}
		}
	}
	return pcap.Interface{}, fmt.Errorf("could not find matching pcap.Interface")
}
