// Package util netutils provides some helper network functions.
package util

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pterm/pterm"
)

var ErrNoInterfaceConnectedToTarget = errors.New("no interface connected to any of the target addresses")

type NetInterfaceProvider interface {
	// Returns all network interfaces
	Interfaces() ([]net.Interface, error)

	// Returns IP Addresses of a particular interface.
	AddrsOf(*net.Interface) ([]net.Addr, error)
}

// GetIfaceByIP finds the first network interface whose assigned IP network
// contains IPAddr
//
// It returns ErrNoInterfaceConnectedToTarget
// when no matching interface is found.
func GetIfaceByIP(interfaceProvider NetInterfaceProvider, IPAddr netip.Addr) (*net.Interface, error) {
	allIfaces, err := interfaceProvider.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range allIfaces {
		addrs, err := interfaceProvider.AddrsOf(&iface)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			addr, ok := addr.(*net.IPNet)
			if !ok {
				return nil, fmt.Errorf("could not convert to IPNet")
			}

			if addr.Contains(IPAddr.AsSlice()) {
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
func GetFirstIfaceIPNet(interfaceProvider NetInterfaceProvider, iface *net.Interface, ip6 bool) (*netip.Prefix, error) {
	addrs, err := interfaceProvider.AddrsOf(iface)
	if err != nil {
		return nil, err
	}
	if len(addrs) < 1 {
		return nil, fmt.Errorf("the interface %v has no IP addresses", iface.Name)
	}

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		addr, err := IPNetToPrefix(ipnet)
		if err != nil {
			return nil, err
		}
		if addr.Addr().Is6() == ip6 {
			return &addr, nil
		}
	}

	if ip6 {
		return nil, fmt.Errorf("the interface %v has no IPv6 addresses", iface.Name)
	}
	return nil, fmt.Errorf("the interface %v has no IPv4 addresses", iface.Name)
}

// VerifyInterface validates whether iface is suitable for scanning operations.
//
// The interface must not be loopback, must be administratively up, must be
// running, and must have at least one assigned address as reported by
// interfaceProvider. It returns an error describing the first failed check.
func VerifyInterface(interfaceProvider NetInterfaceProvider, iface *net.Interface) error {
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

// CheckIfAddrIsPartOfNetworks reports whether addr is contained in at least one
// prefix from targets.
//
// The check stops on the first match.
func CheckIfAddrIsPartOfNetworks(targets []netip.Prefix, addr *netip.Addr) bool {
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
	if addr.Bits() == 32 && addr.Addr().Is4() {
		return true
	} else if addr.Bits() == 128 && addr.Addr().Is6() {
		return true
	}
	return false
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
func GetSourceIPFromInterface(interfaceProvider NetInterfaceProvider, iface *net.Interface, targets []netip.Prefix, ip6 bool) (*netip.Addr, error) {
	ifaceAddrs, err := interfaceProvider.AddrsOf(iface)
	if err != nil {
		return nil, err
	}
	if len(ifaceAddrs) < 1 {
		return nil, fmt.Errorf("interface %v has no IP addresses", iface.Name)
	}
	var ifaceAddr *netip.Prefix
outer:
	for _, addr := range ifaceAddrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		addr, err := IPNetToPrefix(ipnet)
		if err != nil {
			return nil, err
		}

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

// ParseIPRange parses a compact IPv4 range in the form "a.b.c.x-y" and returns
// one host prefix per address in the inclusive range [x, y].
//
// Example: "10.1.1.1-50" expands to 50 /32 prefixes from 10.1.1.1 to 10.1.1.50.
//
// The function validates that the input is non-empty, that a final-octet range
// is present, and that bounds satisfy 0 <= x <= y <= 255. It returns an error
// for malformed ranges or invalid IP addresses.
func ParseIPRange(s string) ([]netip.Prefix, error) {
	// format: 10.1.1.1-50
	if s == "" {
		return nil, fmt.Errorf("error parsing target %v -> Invalid range", s)
	}

	IPPrefixes := make([]netip.Prefix, 0)
	dashIndex := strings.LastIndex(s, "-")
	if dashIndex >= len(s) {
		return nil, fmt.Errorf("error parsing target -> %v", s)
	}
	lastDotIndex := strings.LastIndex(s, ".")
	if lastDotIndex == -1 {
		return nil, fmt.Errorf("error parsing -> %v", s)
	}
	baseIP := s[:lastDotIndex+1]
	lower, err := strconv.Atoi(s[lastDotIndex+1 : dashIndex])
	if err != nil {
		return nil, fmt.Errorf("error parsing target %v -> %v", s, err)
	}
	upper, err := strconv.Atoi(s[dashIndex+1:])
	if err != nil {
		return nil, fmt.Errorf("error parsing target %v -> %v", s, err)
	}
	if lower > upper {
		return nil, fmt.Errorf("error parsing target %v -> invalid range", s)
	} else if upper >= 256 {
		return nil, fmt.Errorf("error parsing target %v -> range cannot go above 255", s)
	} else if lower < 0 {
		return nil, fmt.Errorf("error parsing target %v -> range cannot be below zero", s)
	}

	for i := lower; i <= upper; i++ {
		targetStr := fmt.Sprintf("%v%v", baseIP, i)
		addr, err := netip.ParseAddr(targetStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing target %v -> %v", s, err)
		}
		bitlen := 32
		if addr.Is6() {
			bitlen = 128
		}
		IPPrefixes = append(IPPrefixes, netip.PrefixFrom(addr, bitlen))
	}

	return IPPrefixes, nil
}

// PortsFromString parses a comma-separated list of ports and port ranges into
// a sorted, de-duplicated slice of ports.
//
// Input format examples:
//   - "80"
//   - "22,80,443"
//   - "1-5,22,80-81"
//
// Range entries must be in ascending order (e.g. "10-20"), and each token must
// be a valid integer. The function returns an error for malformed tokens,
// invalid ranges, or non-numeric values.
func PortsFromString(s string) ([]uint, error) {
	// format: 10,1,3,9-15
	commaSeparatedPorts := strings.Split(s, ",")
	targetPorts := make([]uint, 0, 5)

	for _, portSpecString := range commaSeparatedPorts {
		if strings.ContainsRune(portSpecString, '-') {
			// Port Range Provided eg 10-20
			dashIndex := strings.LastIndex(portSpecString, "-")
			if dashIndex >= len(portSpecString) {
				return nil, fmt.Errorf("error parsing port range -> %v", portSpecString)
			}
			lower, err := strconv.Atoi(portSpecString[:dashIndex])
			if err != nil {
				return nil, fmt.Errorf("error parsing port range %v -> %v", portSpecString, err)
			}
			upper, err := strconv.Atoi(portSpecString[dashIndex+1:])
			if err != nil {
				return nil, fmt.Errorf("error parsing port range %v -> %v", portSpecString, err)
			}
			if lower > upper {
				return nil, fmt.Errorf("error parsing target %v -> invalid range", portSpecString)
			}
			for i := lower; i <= upper; i++ {
				targetPorts = append(targetPorts, uint(i))
			}
		} else {
			// Single port presumed
			portNum, err := strconv.Atoi(portSpecString)
			if err != nil {
				return nil, fmt.Errorf("error parsing port specification %v -> %v", portSpecString, err)
			}
			targetPorts = append(targetPorts, uint(portNum))
		}
	}

	slices.Sort(targetPorts)
	return Unique(targetPorts), nil
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

func WaitTimeout(duration time.Duration, timeoutReason string) {
	spinner, err := pterm.DefaultSpinner.Start("Waiting for "+timeoutReason, " timeout")
	if err != nil {
		fmt.Println(err)
	}
	time.Sleep(duration)
	spinner.Success("Timeout Reached.")
}

func ServiceFromGoPacketString(s string) string {
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
