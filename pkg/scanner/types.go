// Package scanner provides functionality for scanning network devices using various network protocols,
// including ARP, NDP, TCP, UDP etc
package scanner

import (
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
	HostState
	// Ports contains the specific details for each port scanned on the host.
	Ports []Port
	// HostName is the resolved DNS name of the host.
	HostName string
	// OpenPorts represents the total count of ports found open.
	OpenPorts int
	// ClosedPorts represents the total count of ports found closed.
	ClosedPorts int
	// FilteredPorts represents the total count of ports where traffic was dropped or blocked (where the port state is uncertain)
	FilteredPorts int
	// AverageRTT is the mean round-trip time for packets sent to the host.
	AverageRTT time.Duration
}

// Port represents a network port with its metadata.
type Port struct {
	// Number is the port number (0-65535).
	Number uint
	// Name is the service name associated with the port.
	Name string
	// Protocol is the transport protocol (tcp, udp, etc.).
	Protocol string
	// State describes the current state of the port.
	State PortState
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

func (s HostState) String() string {
	switch s {
	case HostStateUp:
		return "Up"
	case HostStateDown:
		return "Down"
	default:
		return "unknown"
	}
}

func (r HostResult) TotalNumberOfPorts() int {
	return r.OpenPorts + r.ClosedPorts + r.FilteredPorts
}
