package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/kakeetopius/gscn/internal/util"
)

func TargetsFromString(s string) ([]netip.Prefix, error) {
	// Example: 10.1.1.1/24,10.1.1.1,10.1.1.1-2
	commaSeparatedTargets := strings.Split(s, ",")
	targets := make([]netip.Prefix, 0, 5)

	for _, targetString := range commaSeparatedTargets {
		targetaddrs, err := parseTargetString(targetString)
		if err != nil {
			return nil, err
		}
		targets = append(targets, targetaddrs...)
	}

	return util.Unique(targets), nil
}

func TargetsFromStringWithDNSLookup(s string) ([]netip.Prefix, map[netip.Addr]string, error) {
	// Example: 10.1.1.1/24,10.1.1.1,bing.com,10.1.1.1-2,google.com

	// For dns lookup incase ip address parsing fails.
	resolver := net.Resolver{}
	commaSeparatedTargets := strings.Split(s, ",")
	targets := make([]netip.Prefix, 0, 5)
	hostNames := make(map[netip.Addr]string)

	for _, targetString := range commaSeparatedTargets {
		targetAddr, err := parseTargetString(targetString)
		if err != nil {
			// if some errors occured while Parsing assume it is domain name
			IPs, resolverr := resolver.LookupIP(context.Background(), "ip4", strings.Trim(targetString, " "))
			if resolverr != nil {
				return nil, nil, resolverr
			}
			addr, ok := netip.AddrFromSlice(IPs[0])
			if !ok {
				return nil, nil, fmt.Errorf("could not resolve: %v", targetString)
			}
			targets = append(targets, netip.PrefixFrom(addr, 32))
			hostNames[addr] = targetString
		} else {
			targets = append(targets, targetAddr...)
		}
	}

	return util.Unique(targets), hostNames, nil
}

func parseTargetString(s string) ([]netip.Prefix, error) {
	targets := make([]netip.Prefix, 0)
	if strings.ContainsRune(s, '/') {
		addr, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("error parsing target %v -> %v", s, err)
		}
		targets = append(targets, addr)
	} else if strings.ContainsRune(s, '-') {
		IPRange, err := util.ParseIPRange(s)
		if err != nil {
			return nil, err
		}
		targets = append(targets, IPRange...)
	} else {
		targetStr := fmt.Sprintf("%v/%v", s, 32)
		addr, err := netip.ParsePrefix(targetStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing target %v -> %v", s, err)
		}
		targets = append(targets, addr)
	}
	return targets, nil
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
	return util.Unique(targetPorts), nil
}
