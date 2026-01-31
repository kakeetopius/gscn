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
func GetFirstIfaceIP(iface *net.Interface) (*netip.Prefix, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	if len(addrs) < 1 {
		return nil, fmt.Errorf("the interface %v has no IP addresses", iface.Name)
	}
	addr, err := netip.ParsePrefix(addrs[0].String())
	return &addr, err
}

// VerifyandGetIfaceDetails first verifies that the iface is up and running and is not a loopback interface and then
// checks if destIP is part of any of the networks the interface is connected to. If it is the interface's IP for that network
// is returned together with other details of the interface in an IfaceDetails struct. If not the first IP found on the interface
// is returned in the struct.
func VerifyandGetIfaceDetails(iface *net.Interface, destIP *netip.Prefix) (*IfaceDetails, error) {
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
	var defaultAddr *netip.Prefix
	for i, addr := range ifaceAddrs {
		addr, err := netip.ParsePrefix(addr.String())
		if err != nil {
			return nil, err
		}
		if i == 0 {
			defaultAddr = &addr
		}
		networkAddr := addr.Masked()
		if networkAddr.Contains(destIP.Addr()) {
			ifaceAddr = &addr
			break
		}
	}

	if ifaceAddr == nil {
		ifaceAddr = defaultAddr
	}

	ifaceDetails.IfaceIP = ifaceAddr.Addr()
	ifaceDetails.IPStrWithMask = ifaceAddr.String()
	ifaceDetails.IPStrWithoutMask = ifaceAddr.Addr().String()
	return &ifaceDetails, nil
}
