// Package scanner provides functionality for scanning network devices using various network protocols,
// including ARP, NDP, TCP, UDP etc
package scanner

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

type (
	PortState int
	HostState int
)

const (
	HostStateDown HostState = iota
	HostStateUp
)

const (
	PortStateClosed PortState = iota
	PortStateOpen
	PortStatePossibleFilter // used when  a host's port state cant be known definitevly
)

// Scanner defines the interface for network scanning operations.
type Scanner interface {
	// Scan executes the network scan and returns the scan results
	Scan() (ScanResults, error)
}

// ScanResults defines the interface that all scan result types must implement.
type ScanResults interface {
	Print()
	fmt.Stringer
}

// HostResult is the result of a single host after port scanning
type HostResult struct {
	Addr netip.Addr `json:"ip"`
	// HostState indicates the overall state of the host (e.g., up or down).
	HostState HostState `json:"state"`
	// HostName is the resolved DNS name of the host.
	HostName string `json:"hostname"`
	// OpenPorts represents the total count of ports found open.
	OpenPorts int `json:"open"`
	// ClosedPorts represents the total count of ports found closed.
	ClosedPorts int `json:"closed"`
	// FilteredPorts represents the total count of ports where traffic was dropped or blocked (where the port state is uncertain)
	FilteredPorts int `json:"filtered"`
	// AverageRTT is the mean round-trip time for packets sent to the host.
	AverageRTT time.Duration `json:"rtt"`
	// Ports contains the specific details for each port scanned on the host.
	Ports []Port `json:"ports"`
	// keeps track of where each port is in the Ports slice
	portIndex map[PortNumber]int `json:"-"`
}

// HostResults is a map that associates each host's IP address with its corresponding scan result.
type HostResults map[netip.Addr]HostResult

type PortNumber uint16

// Port represents a network port with its metadata.
type Port struct {
	// Number is the port number (0-65535).
	Number PortNumber `json:"number"`
	// Name is the service name associated with the port.
	Name string `json:"name"`
	// Protocol is the transport protocol (tcp, udp, etc.).
	Protocol string `json:"protocol"`
	// State describes the current state of the port.
	State PortState `json:"state"`
}

func (p PortState) String() string {
	switch p {
	case PortStateOpen:
		return "open"
	case PortStateClosed:
		return "closed"
	case PortStatePossibleFilter:
		return "open | filtered"
	default:
		return "unknown"
	}
}

func (p PortState) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (s HostState) String() string {
	switch s {
	case HostStateUp:
		return "up"
	case HostStateDown:
		return "down"
	default:
		return "unknown"
	}
}

func (s HostState) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s HostResults) MarshalJSON() ([]byte, error) {
	vals := make([]HostResult, 0, len(s))
	for _, v := range s {
		vals = append(vals, v)
	}
	return json.Marshal(vals)
}

func (s HostResult) TotalNumberOfPorts() int {
	return s.OpenPorts + s.ClosedPorts + s.FilteredPorts
}
