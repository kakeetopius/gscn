package find

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/pterm/pterm"
)

type IfaceDetails struct {
	Name             string
	Index            int
	ifaceIP          netip.Addr
	ifaceMac         net.HardwareAddr
	ipStrWithMask    string
	ipStrWithoutMask string
	macStr           string
}

func getDevIface(toFind *netip.Addr) (*net.Interface, error) {
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

func verifyInterface(iface *net.Interface) (*IfaceDetails, error) {
	if iface.Flags&net.FlagLoopback != 0 {
		return nil, fmt.Errorf("cannot scan on a loopback interface")
	} else if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("interface %v is administratively down", iface.Name)
	} else if iface.Flags&net.FlagRunning == 0 {
		return nil, fmt.Errorf("interface %v is not running", iface.Name)
	}

	ifaceDetails := IfaceDetails{}
	ifaceDetails.Name = iface.Name
	ifaceDetails.ifaceMac = iface.HardwareAddr
	ifaceDetails.macStr = iface.HardwareAddr.String()
	ifaceDetails.Index = iface.Index

	ifaceAddrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	if (len(ifaceAddrs) < 1) {
		return nil, fmt.Errorf("interface %v has no IP addresses", iface.Name)
	}
	ifaceAddr, err := netip.ParsePrefix(ifaceAddrs[0].String())
	if err != nil {
		return nil, err
	}
	ifaceDetails.ifaceIP = ifaceAddr.Addr()
	ifaceDetails.ipStrWithMask = ifaceAddr.String()
	ifaceDetails.ipStrWithoutMask = ifaceAddr.Addr().String()
	return &ifaceDetails, nil
}

func getHostNames(resultSet []Results) {
	fmt.Println()
	pterm.Info.Println("Trying to resolve hostnames")
	numHosts := len(resultSet)

	bar, err := pterm.DefaultProgressbar.WithTotal(numHosts).Start()
	if err != nil {
		fmt.Println(err)
	}
	for i := range resultSet {
		names, err := net.LookupAddr(resultSet[i].ipAddr)
		if err == nil && len(names) > 0 {
			resultSet[i].hostName = names[0]
		}
		bar.Increment()
	}
	bar.Stop()
}

