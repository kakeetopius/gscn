// Package netutils provides some helper network functions.
package netutils

import (
	"fmt"
	"net"
	"net/netip"
)

type IfaceDetails struct {
	IfaceIP          netip.Addr
	IPStrWithMask    string
	IPStrWithoutMask string
	MacStr           string
	*net.Interface
}

// GetIfaceByIP gets an interface on the host machine that has an address which matches IPAddr.
func GetIfaceByIP(IPAddr netip.Addr) (*net.Interface, error) {
	allIfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range allIfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			addr, err := netip.ParsePrefix(addr.String())
			if err != nil {
				return nil, err
			}
			// converting the interface to network address and checking if the address(es) to scan are part of that network
			addr = addr.Masked()
			if addr.Contains(IPAddr) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface connected to that network")
}

// GetFirstIfaceIP gets the first IP address on the interface iface.
func GetFirstIfaceIP(iface *net.Interface, ip6 bool) (*netip.Prefix, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	if len(addrs) < 1 {
		return nil, fmt.Errorf("the interface %v has no IP addresses", iface.Name)
	}
	if ip6 {
		for _, addr := range addrs {
			addr, aerr := netip.ParsePrefix(addr.String())
			if aerr != nil {
				continue
			}
			if addr.Addr().Is6() {
				return &addr, nil
			}
		}
		return nil, fmt.Errorf("the interface %v has no IPv6 addresses", iface.Name)
	}

	for _, addr := range addrs {
		addr, aerr := netip.ParsePrefix(addr.String())
		if aerr != nil {
			continue
		}
		if addr.Addr().Is4() {
			return &addr, nil
		}
	}
	return nil, fmt.Errorf("the interface %v has no IPv4 addresses", iface.Name)
}

// VerifyandGetIfaceDetails first verifies that the iface is up and running and is not a loopback interface and then
// checks if destIP is part of any of the networks the interface is connected to. If it is the interface's IP for that network
// is returned together with other details of the interface in an IfaceDetails struct. If not the first IP found on the interface
// is returned in the struct. The boolean ip6 if true only IPv6 addresses are considered else only IPv4 addresses.
func VerifyandGetIfaceDetails(iface *net.Interface, destIP *netip.Prefix, ip6 bool) (*IfaceDetails, error) {
	if iface.Flags&net.FlagLoopback != 0 {
		return nil, fmt.Errorf("cannot scan on a loopback interface")
	} else if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("interface %v is administratively down", iface.Name)
	} else if iface.Flags&net.FlagRunning == 0 {
		return nil, fmt.Errorf("interface %v is not running", iface.Name)
	}

	ifaceDetails := IfaceDetails{}
	ifaceDetails.Interface = iface
	ifaceDetails.MacStr = iface.HardwareAddr.String()

	ifaceAddrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	if len(ifaceAddrs) < 1 {
		return nil, fmt.Errorf("interface %v has no IP addresses", iface.Name)
	}

	var ifaceAddr *netip.Prefix

	for _, addr := range ifaceAddrs {
		addr, err := netip.ParsePrefix(addr.String())
		if err != nil {
			return nil, err
		}
		if ip6 && !addr.Addr().Is6() {
			continue
		} else if !addr.Addr().Is4() {
			continue
		}
		networkAddr := addr.Masked()
		if networkAddr.Contains(destIP.Addr()) {
			ifaceAddr = &addr
			break
		}
	}

	if ip6 && ifaceAddr == nil {
		defaultIP6Addr, err := GetFirstIfaceIP(iface, true)
		if err != nil {
			return nil, err
		}
		if defaultIP6Addr == nil {
			return nil, fmt.Errorf("no IPv6 addresses found on interface %v", iface.Name)
		}
		ifaceAddr = defaultIP6Addr
	} else if ifaceAddr == nil {
		defaultIP4Addr, err := GetFirstIfaceIP(iface, false)
		if err != nil {
			return nil, err
		}
		if defaultIP4Addr == nil {
			return nil, fmt.Errorf("no IPv4 addresses found on interface %v", iface.Name)
		}
		ifaceAddr = defaultIP4Addr
	}

	ifaceDetails.IfaceIP = ifaceAddr.Addr()
	ifaceDetails.IPStrWithMask = ifaceAddr.String()
	ifaceDetails.IPStrWithoutMask = ifaceAddr.Addr().String()
	return &ifaceDetails, nil
}
