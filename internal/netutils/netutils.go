// Package netutils provides some helper network functions.
package netutils

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
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
		addr, err := ipNetToPrefix(ipnet)
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

func ipNetToPrefix(ipnet *net.IPNet) (netip.Prefix, error) {
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
		addr, err := ipNetToPrefix(ipnet)
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

func DiscoverTargetsFromString(s string) ([]netip.Prefix, error) {
	// Example: 10.1.1.1/24,10.1.1.1,10.1.1.1-2
	commaSeparatedTargets := strings.Split(s, ",")
	targets := make([]netip.Prefix, 0, 5)

	for _, targetString := range commaSeparatedTargets {
		if strings.ContainsRune(targetString, '/') {
			addr, err := netip.ParsePrefix(targetString)
			if err != nil {
				return nil, fmt.Errorf("error parsing target %v -> %v", targetString, err)
			}
			targets = append(targets, addr)
		} else if strings.ContainsRune(targetString, '-') {
			dashIndex := strings.LastIndex(targetString, "-")
			if dashIndex >= len(targetString) {
				return nil, fmt.Errorf("error parsing target -> %v", targetString)
			}
			lastDotIndex := strings.LastIndex(targetString, ".")
			if lastDotIndex == -1 {
				return nil, fmt.Errorf("error parsing -> %v", targetString)
			}
			baseIP := targetString[:lastDotIndex+1]
			lower, err := strconv.Atoi(targetString[lastDotIndex+1 : dashIndex])
			if err != nil {
				return nil, fmt.Errorf("error parsing target %v -> %v", targetString, err)
			}
			upper, err := strconv.Atoi(targetString[dashIndex+1:])
			if err != nil {
				return nil, fmt.Errorf("error parsing target %v -> %v", targetString, err)
			}
			if lower > upper {
				return nil, fmt.Errorf("error parsing target %v -> invalid range", targetString)
			} else if upper >= 256 {
				return nil, fmt.Errorf("error parsing target %v -> range cannot go above 255", targetString)
			} else if lower < 0 {
				return nil, fmt.Errorf("error parsing target %v -> range cannot be below zero", targetString)
			}

			for i := lower; i <= upper; i++ {
				targetStr := fmt.Sprintf("%v%v/32", baseIP, i)
				addr, err := netip.ParsePrefix(targetStr)
				if err != nil {
					return nil, fmt.Errorf("error parsing target %v -> %v", targetString, err)
				}
				targets = append(targets, addr)
			}
		} else {
			targetStr := fmt.Sprintf("%v/%v", targetString, 32)
			addr, err := netip.ParsePrefix(targetStr)
			if err != nil {
				return nil, fmt.Errorf("error parsing target %v -> %v", targetString, err)
			}
			targets = append(targets, addr)
		}
	}

	return Unique(targets), nil
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
