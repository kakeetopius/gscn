package discover

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/pterm/pterm"
)

type IfaceDetails struct {
	ifaceIP          netip.Addr
	ipStrWithMask    string
	ipStrWithoutMask string
	macStr           string
	*net.Interface
}

func getIfaceByIP(toFind *netip.Addr) (*net.Interface, error) {
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
			if addr.Contains(*toFind) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("no non-loopback interface connected to that network")
}

func verifyandGetIfaceDetails(iface *net.Interface, addrToUse *netip.Prefix) (*IfaceDetails, error) {
	if iface.Flags&net.FlagLoopback != 0 {
		return nil, fmt.Errorf("cannot scan on a loopback interface")
	} else if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("interface %v is administratively down", iface.Name)
	} else if iface.Flags&net.FlagRunning == 0 {
		return nil, fmt.Errorf("interface %v is not running", iface.Name)
	}

	ifaceDetails := IfaceDetails{}
	ifaceDetails.Interface = iface
	ifaceDetails.macStr = iface.HardwareAddr.String()

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
		if networkAddr.Contains(addrToUse.Addr()) {
			ifaceAddr = &addr
			break
		}
	}

	if ifaceAddr == nil {
		ifaceAddr = defaultAddr
	}

	ifaceDetails.ifaceIP = ifaceAddr.Addr()
	ifaceDetails.ipStrWithMask = ifaceAddr.String()
	ifaceDetails.ipStrWithoutMask = ifaceAddr.Addr().String()
	return &ifaceDetails, nil
}

func getHostNames(resultSet []Results, timeout time.Duration) {
	fmt.Println()
	pterm.Info.Println("Trying to resolve hostnames")
	numHosts := len(resultSet)

	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Second)
	defer cancel()

	resolver := net.Resolver{}
	resolver.PreferGo = true

	bar, err := pterm.DefaultProgressbar.WithTotal(numHosts).Start()
	if err != nil {
		fmt.Println(err)
	}
	for i := range resultSet {
		names, err := resolver.LookupAddr(ctx, resultSet[i].ipAddr)
		if err == nil && len(names) > 0 {
			resultSet[i].hostName = names[0]
		}
		bar.Increment()
	}
	bar.Stop()
}
