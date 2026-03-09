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
)

type IfaceOpts struct {
	*net.Interface
}

var ErrNoInterfaceConnectedToTarget = errors.New("no interface connected to any of the target addresses")

type NetInterfaceProvider interface {
	// Returns all network interfaces
	Interfaces() ([]net.Interface, error)

	// Returns IP Addresses of a particular interface.
	AddrsOf(*net.Interface) ([]net.Addr, error)
}

// GetIfaceByIP gets an interface on the host machine that has an address which matches IPAddr.
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

// GetFirstIfaceIPNet gets the address(netip.Prefix) of the first IP network on the interface iface.
// The boolean ip6 if true only IPv6 addresses are considered else only IPv4 addresses.
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

func CheckIfAddrIsPartOfNetworks(targets []netip.Prefix, addr *netip.Addr) bool {
	for _, target := range targets {
		if target.Contains(*addr) {
			return true
		}
	}
	return false
}

func HostsInNetworks(targets []netip.Prefix) int {
	numHosts := 0
	for _, target := range targets {
		networkAddress := target.Masked()
		numHosts += int(math.Pow(2, float64(32-networkAddress.Bits())))
	}
	return numHosts
}

func OnlyIPInRange(addr netip.Prefix) bool {
	if addr.Bits() == 32 && addr.Addr().Is4() {
		return true
	} else if addr.Bits() == 128 && addr.Addr().Is6() {
		return true
	}
	return false
}

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
