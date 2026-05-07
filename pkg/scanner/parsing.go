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

type ipParseError struct {
	skipResolving bool
	error
}

// TargetsFromString parses a comma-separated string of network targets and returns
// a deduplicated slice of netip.Prefix values.
//
// The input string format supports multiple target types:
//   - CIDR notation: "10.1.1.1/24, 2001:abcd::1/64"
//   - Single IP addresses: "10.1.1.1"
//   - IP ranges: "10.1.1.1-2"
//
// Example: "10.1.1.1/24,10.1.1.1,10.1.1.1-2"
//
// Returns an error if any target string cannot be parsed.
func TargetsFromString(s string) ([]netip.Prefix, error) {
	targetStrings := strings.Split(s, ",")
	targets := make([]netip.Prefix, 0, 5)

	for _, targetString := range targetStrings {
		if targetString == "" {
			return nil, fmt.Errorf("error parsing targets -> one of the targets is empty")
		}
		targetaddrs, err := parseTargetString(targetString)
		if err != nil {
			return nil, err
		}
		targets = append(targets, targetaddrs...)
	}

	return util.Unique(targets), nil
}

// TargetsFromStringWithDNSLookup parses a comma-separated string of network targets
// and performs DNS lookups for unresolvable addresses, treating them as domain names.
//
// The input string format supports multiple target types:
//   - CIDR notation: "10.1.1.1/24, 2001:abcd::1/64"
//   - Single IP addresses: "10.1.1.1"
//   - IP ranges: "10.1.1.1-2"
//   - Domain names: "bing.com", "google.com"
//
// Example: "10.1.1.1/24,10.1.1.1,bing.com,10.1.1.1-2,google.com"
//
// Returns:
//   - A deduplicated slice of netip.Prefix values
//   - A map of resolved IP addresses to their original hostname strings
//   - An error if DNS lookup fails for any unresolvable target
func TargetsFromStringWithDNSLookup(s string) ([]netip.Prefix, map[netip.Addr]string, error) {
	// For dns lookup incase ip address parsing fails.
	resolver := net.Resolver{}
	commaSeparatedTargets := strings.Split(s, ",")
	targets := make([]netip.Prefix, 0, 5)
	hostNames := make(map[netip.Addr]string)

	for _, targetString := range commaSeparatedTargets {
		if targetString == "" {
			return nil, nil, fmt.Errorf("error parsing targets -> one of the targets is empty")
		}
		targetAddr, err := parseTargetString(targetString)
		if err != nil {
			if err, ok := err.(ipParseError); ok && err.skipResolving {
				return nil, nil, err
			}

			// if some errors occured while Parsing assume it is domain name
			IPs, resolverErr := resolver.LookupIP(context.Background(), "ip4", strings.TrimSpace(targetString))
			if resolverErr != nil {
				return nil, nil, resolverErr
			}
			if len(IPs) == 0 {
				return nil, nil, fmt.Errorf("no ips returned after resolving %v", targetString)
			}
			addr, ok := netip.AddrFromSlice(IPs[0])
			if !ok {
				return nil, nil, fmt.Errorf("could not resolve: %v", targetString)
			}
			prefixLen := 32
			if addr.Is6() {
				prefixLen = 128
			}
			targets = append(targets, netip.PrefixFrom(addr, prefixLen))
			hostNames[addr] = targetString
		} else {
			targets = append(targets, targetAddr...)
		}
	}

	return util.Unique(targets), hostNames, nil
}

// parseTargetString parses a single target string and returns a slice of netip.Prefix values.
//
// The input string format supports three target types:
//   - CIDR notation: "10.1.1.1/24" - parsed directly as a prefix
//   - IP range: "10.1.1.1-10.1.1.5" - parsed by parseIPRange and converted to individual prefixes
//   - Single IP address: "10.1.1.1" - treated as a /32 prefix
//
// Returns an error if the target string cannot be parsed in any of the supported formats.
func parseTargetString(s string) ([]netip.Prefix, error) {
	targets := make([]netip.Prefix, 0)
	if strings.ContainsRune(s, '/') {
		addr, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		targets = append(targets, addr)
	} else if strings.ContainsRune(s, '-') {
		IPRange, err := parseIPRange(s)
		if err != nil {
			return nil, err
		}
		targets = append(targets, IPRange...)
	} else {
		targetStr := fmt.Sprintf("%v/%v", s, 32) // first assume it is IPv4 so use a /32 to indicate a single IP network.
		addr, err := netip.ParsePrefix(targetStr)
		if err != nil {
			return nil, err
		}
		if addr.Addr().Is6() {
			prefixLen := 128
			addr = netip.PrefixFrom(addr.Addr(), prefixLen) // convert now to a /128 IPv6 address
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
	portStrings := strings.Split(s, ",")
	targetPorts := make([]uint, 0, len(portStrings))

	for _, portString := range portStrings {
		if strings.ContainsRune(portString, '-') {
			// Port Range Provided eg 10-20
			dashIndex := strings.LastIndex(portString, "-") // assured to exist due to the above check
			if dashIndex == len(portString)-1 {             // if '-' is at the end
				return nil, fmt.Errorf("error parsing port range %v -> invalid range", portString)
			}

			var lower int
			var err error
			if dashIndex > 0 {
				// if dash is at the start (index 0), lower remains 0
				lower, err = strconv.Atoi(portString[:dashIndex])
				if err != nil {
					return nil, fmt.Errorf("error parsing port range %v -> %v", portString, err)
				}
			}

			upper, err := strconv.Atoi(portString[dashIndex+1:])
			if err != nil {
				return nil, fmt.Errorf("error parsing port range %v -> %v", portString, err)
			}
			if lower > upper {
				return nil, fmt.Errorf("error parsing port range %v -> invalid range", portString)
			}
			if lower < 0 {
				return nil, fmt.Errorf("error parsing port range %v -> port numbers cannot be below 0", portString)
			}
			if upper > 65535 {
				return nil, fmt.Errorf("error parsing port range %v -> port numbers cannot go above 65535", portString)
			}

			for i := lower; i <= upper; i++ {
				targetPorts = append(targetPorts, uint(i))
			}
		} else {
			// Single port presumed
			portNum, err := strconv.Atoi(portString)
			if err != nil {
				return nil, fmt.Errorf("error parsing port specification %v -> %v", portString, err)
			}
			targetPorts = append(targetPorts, uint(portNum))
		}
	}

	slices.Sort(targetPorts)
	return util.Unique(targetPorts), nil
}

// parseIPRange parses a compact IPv4 and IPv6 range in the form "a.b.c.x-y" and returns
// one host prefix per address in the inclusive range [x, y].
//
// Example: "10.1.1.1-50" expands to 50 /32 prefixes from 10.1.1.1 to 10.1.1.50.
//
// The function validates that the input is non-empty, that a final-octet range
// is present, and that bounds satisfy 0 <= x <= y <= 255. It returns an error
// for malformed ranges or invalid IP addresses.
func parseIPRange(s string) ([]netip.Prefix, error) {
	// format: 10.1.1.1-50 or 2001:acad:abcd::1-10

	ipPrefixes := make([]netip.Prefix, 0)
	dashIndex := strings.LastIndex(s, "-")
	if dashIndex == -1 {
		return nil, fmt.Errorf("error parsing %v -> Invalid Format", s)
	} else if dashIndex == len(s)-1 {
		return nil, fmt.Errorf("error parsing target %v -> Invalid Format", s)
	}

	lastDelimIndex := strings.LastIndex(s, ".") // first presume IPv4
	if lastDelimIndex == -1 {
		lastDelimIndex = strings.LastIndex(s, ":")
		if lastDelimIndex == -1 {
			return nil, fmt.Errorf("error parsing -> %v", s)
		}
	}
	baseIP := s[:lastDelimIndex+1] // baseIP is something like 10.1.1. (with the dot)

	if lastDelimIndex > dashIndex {
		return nil, fmt.Errorf("error parsing target %v -> Invalid Range", s)
	}

	lower, err := strconv.Atoi(s[lastDelimIndex+1 : dashIndex]) // get number from the last dot to the dash.
	if err != nil {
		return nil, fmt.Errorf("error parsing target %v -> %w", s, err)
	}

	upper, err := strconv.Atoi(s[dashIndex+1:]) // get number from after the dash to the end
	if err != nil {
		return nil, fmt.Errorf("error parsing target %v -> %w", s, err)
	}

	if lower > upper {
		return nil, ipParseError{
			error:         fmt.Errorf("error parsing target %v -> invalid range", s),
			skipResolving: true,
		}
	} else if lower < 0 {
		return nil, ipParseError{
			error:         fmt.Errorf("error parsing target %v -> range cannot be below zero", s),
			skipResolving: true,
		}
	}

	if upper-lower > 1000 {
		return nil, ipParseError{
			skipResolving: true,
			error:         fmt.Errorf("range %v is too large. Consider using CIDR notation", s),
		}
	}

	for i := lower; i <= upper; i++ {
		targetStr := baseIP + strconv.Itoa(i)
		addr, err := netip.ParseAddr(targetStr)
		if err != nil {
			return nil, ipParseError{
				error:         fmt.Errorf("error parsing target %v -> %w", s, err),
				skipResolving: true,
			}
		}
		bitlen := 32
		if addr.Is6() {
			bitlen = 128
		}
		ipPrefixes = append(ipPrefixes, netip.PrefixFrom(addr, bitlen))
	}

	return ipPrefixes, nil
}
