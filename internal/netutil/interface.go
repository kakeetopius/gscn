package netutil

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/google/gopacket/layers"
)

// NetInterfaceProvider is an interface that abstracts the retrieval of network interfaces.
type NetInterfaceProvider interface {
	// Returns all network interfaces
	Interfaces() ([]Interface, error)

	// Returns an interface with the given name
	InterfaceByName(name string) (Interface, error)

	// Returns an interface with the given index
	InterfaceByIndex(index int) (Interface, error)
}

type realNetInterfaceProvider struct {
	interfaces    []Interface
	ifaceNameIdx  map[string]int
	ifaceIndexIdx map[int]int
}

func (r *realNetInterfaceProvider) Interfaces() ([]Interface, error) {
	return r.interfaces, nil
}

func (r *realNetInterfaceProvider) InterfaceByName(name string) (Interface, error) {
	if index, ok := r.ifaceNameIdx[name]; ok {
		return r.interfaces[index], nil
	}

	return Interface{}, fmt.Errorf("interface %q not found", name)
}

func (r *realNetInterfaceProvider) InterfaceByIndex(ifIndex int) (Interface, error) {
	if index, ok := r.ifaceIndexIdx[ifIndex]; ok {
		return r.interfaces[index], nil
	}

	return Interface{}, fmt.Errorf("interface with index %q not found", ifIndex)
}

type Interface struct {
	net.Interface

	// PcapName is the interface's name that can be used by pcap.OpenLive() function to set up a pcap handle. On linux it is the same as the Name field
	// in net.Interface but on Windows it is different.
	PcapName string

	LinkType layers.LinkType

	// Addresses of the interface all converted to netip.Prefix.
	allAddresses []netip.Prefix
	ip4Addresses []netip.Prefix
	ip6Addresses []netip.Prefix
}

// AllAddrs returns all addresses of the interface as netip.Prefix.
func (i Interface) AllAddrs() []netip.Prefix {
	return i.allAddresses
}

// IP4Addrs returns all IPv4 addresses of the interface as netip.Prefix.
func (i Interface) IP4Addrs() []netip.Prefix {
	return i.ip4Addresses
}

// IP6Addrs returns all IPv6 addresses of the interface as netip.Prefix.
func (i Interface) IP6Addrs() []netip.Prefix {
	return i.ip6Addresses
}

func (i *Interface) AppendPrefix(addrs ...netip.Prefix) {
	for _, addr := range addrs {
		i.allAddresses = append(i.allAddresses, addr)

		if addr.Addr().Is4() {
			i.ip4Addresses = append(i.ip4Addresses, addr)
		} else {
			i.ip6Addresses = append(i.ip6Addresses, addr)
		}
	}
}

func (i *Interface) AppendNetAddr(addrs ...net.Addr) {
	for _, addr := range addrs {
		prefix, aerr := AddrToPrefix(addr)
		if aerr != nil {
			continue
		}
		i.allAddresses = append(i.allAddresses, prefix)

		if prefix.Addr().Is4() {
			i.ip4Addresses = append(i.ip4Addresses, prefix)
		} else {
			i.ip6Addresses = append(i.ip6Addresses, prefix)
		}
	}
}

func (i Interface) FirstIP4Addr() (*netip.Prefix, error) {
	return i.FirstAddr(syscall.AF_INET)
}

func (i Interface) FirstIP6Addr() (*netip.Prefix, error) {
	return i.FirstAddr(syscall.AF_INET6)
}

// FirstAddr returns the first interface address that matches the
// requested IP family and converts it to netip.Prefix.
//
// An error is returned if address lookup fails, the interface has no addresses, or no address
// of the requested family is found.
func (i Interface) FirstAddr(family AddressFamily) (*netip.Prefix, error) {
	if len(i.allAddresses) == 0 {
		return nil, fmt.Errorf("the interface %v has no IP addresses", i.Name)
	}

	var addrs []netip.Prefix

	switch family {
	case syscall.AF_INET:
		addrs = i.ip4Addresses
	case syscall.AF_INET6:
		addrs = i.ip6Addresses
	default:
		return nil, fmt.Errorf("unknown address family: %v", family)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("the interface %s has no %s addresses", i.Name, family.String())
	}

	return &addrs[0], nil
}

// AddrOnSameNetworkAs returns the first interface address that is on the same network as addr.
func (i Interface) AddrOnSameNetworkAs(addr netip.Addr) (netip.Addr, error) {
	if len(i.allAddresses) == 0 {
		return netip.Addr{}, fmt.Errorf("the interface %v has no IP addresses", i.Name)
	}

	for _, ifaceAddr := range i.allAddresses {
		if ifaceAddr.Masked().Contains(addr) {
			return ifaceAddr.Addr(), nil
		}
	}

	return netip.Addr{}, fmt.Errorf("could not get interface address on the same network as: %v", addr.String())
}
