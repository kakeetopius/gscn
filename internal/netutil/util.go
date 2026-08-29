// Package netutil netutils provides some helper network functions.
package netutil

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/endobit/oui"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type AddressFamily uint16

func AddressFamilyOf(addr netip.Addr) AddressFamily {
	if addr.Is4() {
		return syscall.AF_INET
	} else if addr.Is6() {
		return syscall.AF_INET6
	}

	return syscall.AF_UNSPEC
}

func (f AddressFamily) String() string {
	switch f {
	case syscall.AF_INET:
		return "ipv4"
	case syscall.AF_INET6:
		return "ipv6"
	}

	return ""
}

var ErrNoInterfaceConnectedToTarget = errors.New("no interface connected to any of the target addresses")

// GetIfaceByIP finds the first network interface whose assigned IP network
// is equal to IPAddr
//
// It returns ErrNoInterfaceConnectedToTarget
// when no matching interface is found.
func GetIfaceByIP(interfaceProvider NetInterfaceProvider, IPAddr netip.Addr) (*Interface, error) {
	allIfaces, err := interfaceProvider.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range allIfaces {
		addrs := iface.allAddresses
		for _, addr := range addrs {
			if addr.Addr() == IPAddr {
				return &iface, nil
			}
		}
	}

	return nil, ErrNoInterfaceConnectedToTarget
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

// AddrToPrefix converts a net.Addr to a netip.Prefix.
// It returns an error if the address is not an *net.IPNet or if conversion fails.
func AddrToPrefix(addr net.Addr) (netip.Prefix, error) {
	ipnet, ok := addr.(*net.IPNet)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("invalid IPNet")
	}
	return IPNetToPrefix(ipnet)
}

// AddrSliceToPrefixSlice converts a slice of net.Addr to a slice of netip.Prefix.
// It returns an error if any address is not an *net.IPNet or if conversion fails.
func AddrSliceToPrefixSlice(ifaceAddrs []net.Addr) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(ifaceAddrs))
	for _, addr := range ifaceAddrs {
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

// HostsInIP4Network returns the total number of usable IPv4 addresses represented by
// the provided prefixes.
// The calculation is IPv4-specific.
func HostsInIP4Network(targets []netip.Prefix) int {
	numHosts := 0
	for _, target := range targets {
		if !target.Addr().Is4() {
			continue
		}
		networkAddress := target.Masked()
		numHosts += int(math.Pow(2, float64(32-networkAddress.Bits())))
		if !target.IsSingleIP() {
			numHosts = numHosts - 2 // remove network and broadcast addresses
		}
	}
	return numHosts
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

func TCPServiceName(portNum uint16) string {
	return cleanServiceName(layers.TCPPort(portNum).String())
}

func UDPServiceName(portNum uint16) string {
	return cleanServiceName(layers.UDPPort(portNum).String())
}

// cleanServiceName extracts the service name from a gopacket-style
// string in the format "port(service)" (for example, "80(http)").
// It returns an empty string when the input is empty, malformed, or does not
// include both opening and closing parentheses.
func cleanServiceName(s string) string {
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
func VerifyInterface(iface *Interface) error {
	zeroMac := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	if iface.Flags&net.FlagLoopback != 0 {
		return fmt.Errorf("cannot scan on a loopback interface")
	} else if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %v is administratively down", iface.Name)
	} else if iface.Flags&net.FlagRunning == 0 {
		return fmt.Errorf("interface %v is not running", iface.Name)
	} else if iface.HardwareAddr == nil {
		return fmt.Errorf("interface %v has no mac address", iface.Name)
	} else if slices.Equal(zeroMac, iface.HardwareAddr) {
		return fmt.Errorf("interface %v has an invalid mac address", iface.Name)
	}

	if len(iface.allAddresses) < 1 {
		return fmt.Errorf("interface %v has no IP addresses", iface.Name)
	}

	return nil
}

// ReverseLookup performs a reverse DNS lookup for the given IP address and returns the first resolved hostname.
func ReverseLookup(ctx context.Context, addr string) string {
	resolver := net.Resolver{}
	resolver.PreferGo = true

	names, err := resolver.LookupAddr(ctx, addr)
	if err == nil && len(names) > 0 {
		return names[0]
	}
	return ""
}

func GetLinktypeOf(ifacePcapName string) (layers.LinkType, error) {
	handle, err := pcap.OpenLive(ifacePcapName, 1, false, time.Millisecond)
	if err != nil {
		return 0, err
	}
	defer handle.Close()
	return handle.LinkType(), nil
}

func LoopbackInterface(p NetInterfaceProvider) (*Interface, error) {
	ifaces, err := p.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("could not find the loopback interface")
}
