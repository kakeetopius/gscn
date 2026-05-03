// Package util netutils provides some helper network functions.
package util

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"

	"github.com/endobit/oui"
)

var ErrNoInterfaceConnectedToTarget = errors.New("no interface connected to any of the target addresses")

type Interface struct {
	// PcapName is the interface's name that can be used by pcap.OpenLive() function to set up a pcap handle. On linux it is the same as the Name field
	// in net.Interface but on Windows it is different.
	PcapName string

	net.Interface

	// Addresses of the interface all converted to netip.Prefix.
	address []netip.Prefix
}

type NetInterfaceProvider interface {
	// Returns all network interfaces
	Interfaces() ([]Interface, error)

	// Returns IP Addresses of a particular interface.
	AddrsOf(*Interface) []netip.Prefix

	// Returns an interface with the given name
	InterfaceByName(name string) (*Interface, error)
}

// GetIfaceByIP finds the first network interface whose assigned IP network
// contains IPAddr
//
// It returns ErrNoInterfaceConnectedToTarget
// when no matching interface is found.
func GetIfaceByIP(interfaceProvider NetInterfaceProvider, IPAddr netip.Addr) (*Interface, error) {
	allIfaces, err := interfaceProvider.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range allIfaces {
		addrs := interfaceProvider.AddrsOf(&iface)
		for _, addr := range addrs {
			if addr.Contains(IPAddr) {
				return &iface, nil
			}
		}
	}

	return nil, ErrNoInterfaceConnectedToTarget
}

// GetFirstIfaceIPNet returns the first interface address that matches the
// requested IP family and converts it to netip.Prefix.
//
// When ip6 is true, it searches for an IPv6 address; otherwise it searches for
// IPv4. An error is returned if address lookup fails, the interface has no addresses, conversion fails, or no address
// of the requested family is found.
func GetFirstIfaceIPNet(interfaceProvider NetInterfaceProvider, iface *Interface, ip6 bool) (*netip.Prefix, error) {
	addrs := interfaceProvider.AddrsOf(iface)
	if len(addrs) < 1 {
		return nil, fmt.Errorf("the interface %v has no IP addresses", iface.Name)
	}

	for _, addr := range addrs {
		if addr.Addr().Is6() == ip6 {
			return &addr, nil
		}
	}

	if ip6 {
		return nil, fmt.Errorf("the interface %v has no IPv6 addresses", iface.Name)
	}
	return nil, fmt.Errorf("the interface %v has no IPv4 addresses", iface.Name)
}

// IPNetToPrefix converts a net.IPNet value into its netip.Prefix equivalent.
//
// It returns an error when the IP in ipnet cannot be converted to a valid
// netip.Addr.
func IPNetToPrefix(ipnet *net.IPNet) (netip.Prefix, error) {
	ip := ipnet.IP

	// Check to see if the ipnet is IPv4 and if so change the slice to a 4 byte slice to allow AddrFromSlice to return correct representation
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("invalid IPNet")
	}

	ones, _ := ipnet.Mask.Size()

	return netip.PrefixFrom(addr, ones), nil
}

// AddrSliceToPrefixSlice converts a slice of net.Addr to a slice of netip.Prefix.
// It returns an error if any address is not an *net.IPNet or if conversion fails.
func AddrSliceToPrefixSlice(addrs []net.Addr) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(addrs))
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			return nil, fmt.Errorf("invalid IPNet")
		}
		prefix, err := IPNetToPrefix(ipnet)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}

// AddrIsPartOfNetworks reports whether addr is contained in at least one
// prefix from targets.
//
// The check stops on the first match.
func AddrIsPartOfNetworks(targets []netip.Prefix, addr *netip.Addr) bool {
	for _, target := range targets {
		if target.Contains(*addr) {
			return true
		}
	}
	return false
}

// HostsInIP4Network returns the total number of IPv4 addresses represented by
// the provided prefixes.
// The calculation is IPv4-specific.
func HostsInIP4Network(targets []netip.Prefix) int {
	numHosts := 0
	for _, target := range targets {
		networkAddress := target.Masked()
		numHosts += int(math.Pow(2, float64(32-networkAddress.Bits())))
	}
	return numHosts
}

// OnlyIPInRange reports whether addr represents exactly one host address.
//
// It returns true for IPv4 /32 and IPv6 /128 prefixes, and false for all
// broader network prefixes.
func OnlyIPInRange(addr netip.Prefix) bool {
	return addr.IsSingleIP()
}

// GetSourceIPFromInterface returns the source IP address from the given network interface that matches the provided targets.
// It attempts to find an IP address (IPv4 or IPv6 as specified by ip6) on the interface that is in the same network as any of the targets.
// If no matching address is found, it falls back to the first available address of the requested IP version.
//
// Parameters:
//   - interfaceProvider: Provides methods to retrieve addresses from interfaces.
//   - iface: The network interface to search for addresses.
//   - targets: A slice of netip.Prefix representing target networks to match.
//   - ip6: If true, searches for IPv6 addresses; otherwise, searches for IPv4.
//
// Returns:
//   - *netip.Addr: The selected source IP address.
//   - error: Any error encountered during address selection.
func GetSourceIPFromInterface(interfaceProvider NetInterfaceProvider, iface *Interface, targets []netip.Prefix, ip6 bool) (*netip.Addr, error) {
	ifaceAddrs := interfaceProvider.AddrsOf(iface)
	if len(ifaceAddrs) < 1 {
		return nil, fmt.Errorf("interface %v has no IP addresses", iface.Name)
	}
	var ifaceAddr *netip.Prefix
outer:
	for _, addr := range ifaceAddrs {
		if ip6 != addr.Addr().Is6() {
			// if an IPv4 address is needed but the current address is not IPv6 and vice versa
			continue
		}
		networkAddr := addr.Masked()
		// checking to see if any of the targets is on the same network as any of the interfaces' addresses.
		for _, target := range targets {
			if networkAddr.Contains(target.Addr()) {
				ifaceAddr = &addr
				break outer
			}
		}
	}

	// If an address on the same network as one of the targets was not found, default to the fisrt IP address found on the interface of the same address family.
	if ip6 && ifaceAddr == nil {
		defaultIP6Addr, err := GetFirstIfaceIPNet(interfaceProvider, iface, true)
		if err != nil {
			return nil, err
		}
		if defaultIP6Addr == nil {
			return nil, fmt.Errorf("no IPv6 addresses found on interface %v", iface.Name)
		}
		ifaceAddr = defaultIP6Addr
	} else if ifaceAddr == nil {
		defaultIP4Addr, err := GetFirstIfaceIPNet(interfaceProvider, iface, false)
		if err != nil {
			return nil, err
		}
		if defaultIP4Addr == nil {
			return nil, fmt.Errorf("no IPv4 addresses found on interface %v", iface.Name)
		}
		ifaceAddr = defaultIP4Addr
	}
	srcAddr := ifaceAddr.Addr()
	return &srcAddr, nil
}

// Unique returns a new slice containing the first occurrence of each distinct
// value from slice, preserving the original input order.
//
// T must be comparable because values are tracked in a map for O(1) membership
// checks. The returned slice does not share backing storage with the input.
func Unique[T comparable](slice []T) []T {
	seen := make(map[T]struct{})
	results := make([]T, 0, len(slice))

	for _, v := range slice {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			results = append(results, v)
		}
	}
	return results
}

// Service extracts the service name from a gopacket-style
// string in the format "port(service)" (for example, "80(http)").
// It returns an empty string when the input is empty, malformed, or does not
// include both opening and closing parentheses.
func Service(s string) string {
	// format: number(name) eg 80(http)
	if s == "" {
		return s
	}
	firstBracket := strings.Index(s, "(")
	secondBracket := strings.Index(s, ")")
	if firstBracket == -1 || secondBracket == -1 {
		// if gopacket just returned number alone without service
		return ""
	}
	return s[firstBracket+1 : secondBracket]
}

// MACVendor returns the vendor name for a given MAC address.
func MACVendor(mac string) string {
	return oui.Vendor(mac)
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
