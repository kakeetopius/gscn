// Package scanner provides functionality for scanning network devices using various network protocols,
// including ARP, NDP, TCP, UDP etc
package scanner

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/kakeetopius/gscn/internal/notify"
)

type (
	ScanType  int
	PortState int
	HostState int
)

const (
	ARPScan ScanType = iota + 1
	NDPScan
	TCPFullScan
	UDPScan
	PingScan
	WifiScan
)

const (
	HostStateUp HostState = iota + 1
	HostStateDown
)

const (
	PortStateOpen PortState = iota + 1
	PortStateClosed
	PortStatePossibleFilter // used during udp scan when a host's port state cant be known definitevly
)

type MAC net.HardwareAddr

// Scanner defines the interface for network scanning operations.
type Scanner interface {
	// Scan executes the network scan and returns an error if the scan fails.
	Scan() error
	// Results returns the results of the completed scan.
	Results() ScanResults
	// Stats returns statistics about the completed scan.
	Stats() ScanStats
	// SendResultsViaNotifier sends scan results using the configured notifier
	SendResultsViaNotifier() error
	// PrintResults outputs the scan findings to standard output.
	PrintResults()
	// SetNotifier configures the notifier instance used to send the results.
	SetNotifier(n notify.Notifier)
}

// HostResult is the result of a single host after port scanning
type HostResult struct {
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
}

type HostResults map[netip.Addr]HostResult

// Port represents a network port with its metadata.
type Port struct {
	// Number is the port number (0-65535).
	Number uint `json:"number"`
	// Name is the service name associated with the port.
	Name string `json:"name"`
	// Protocol is the transport protocol (tcp, udp, etc.).
	Protocol string `json:"protocol"`
	// State describes the current state of the port.
	State PortState `json:"state"`
}

// ScanResults defines the interface that all scan result types must implement.
// It provides methods to convert results to a string representation and identify
// the specific type of scan result.
type ScanResults interface {
	// String returns a string representation of the scan result.
	String() string
}

type ScanStats any

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

func (s HostResult) TotalNumberOfPorts() int {
	return s.OpenPorts + s.ClosedPorts + s.FilteredPorts
}

func (m MAC) String() string {
	return net.HardwareAddr(m).String()
}

func (m MAC) MarshalJSON() ([]byte, error) {
	return json.Marshal(net.HardwareAddr(m).String())
}

func (r HostResults) String() string {
	stringBuilder := strings.Builder{}
	for addr, result := range r {
		fmt.Fprintf(&stringBuilder, "Results for %v", addr.String())
		if result.HostName == "" {
			fmt.Fprintf(&stringBuilder, "\n")
		} else {
			fmt.Fprintf(&stringBuilder, " (%v)\n", result.HostName)
		}
		for _, port := range result.Ports {
			if port.State == PortStateOpen {
				fmt.Fprintf(&stringBuilder, "%v/%v (%v) -> Open\n", port.Protocol, port.Number, port.Name)
			}
		}
		fmt.Fprintf(&stringBuilder, "Total Ports Scanned: %v\n", result.ClosedPorts+result.OpenPorts)
		fmt.Fprintf(&stringBuilder, "Open Ports: %v\n", result.OpenPorts)
		fmt.Fprintf(&stringBuilder, "Closed Ports: %v\n\n", result.ClosedPorts)
	}
	return stringBuilder.String()
}
