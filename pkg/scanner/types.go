// Package scanner provides functionality for scanning network devices using various network protocols,
// including ARP, NDP, TCP, UDP.
package scanner

// ScanResults defines the interface that all scan result types must implement.
// It provides methods to convert results to a string representation and identify
// the specific type of scan result.
type ScanResults interface {
	// String returns a string representation of the scan result.
	String() string
	// ResultType returns the type of scan result.
	ResultType() ScanResultType
}

type ScanStats any

// Scanner defines the interface for network scanning operations.
//
// It provides methods to configure and execute network scans, retrieve results and statistics,
// and customize scanning behavior.
type Scanner interface {
	// Scan executes the network scan and returns an error if the scan fails.
	Scan() error
	// Results returns the results of the completed scan.
	Results() ScanResults
	// Stats returns statistics about the completed scan.
	Stats() ScanStats
	// SendResultsViaNotifier sends scan results using the configured notifier
	SendResultsViaNotifier() error
}

type ScanResultType int

const (
	ARPScanResultType ScanResultType = iota
	NDPScanResultType
	TCPFullScanScanResultType
	UDPScanResultType
	PingScanResultType
)

type PortState uint8

const (
	PortStateOpen PortState = iota
	PortStateClosed
	PortStatePossibleFilter
)

func (p PortState) String() string {
	var s string
	switch p {
	case PortStateOpen:
		s = "open"
	case PortStateClosed:
		s = "closed"
	case PortStatePossibleFilter:
		s = "open | filtered"
	}

	return s
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

// HostResult is the result of a single host after port scanning
type HostResult struct {
	Ports    map[uint]Port
	HostName string
	HostState
	OpenPorts   int
	ClosedPorts int
}

type HostState int

const (
	HostStateUp HostState = iota
	HostStateDown
)

func (s HostState) String() string {
	switch s {
	case HostStateUp:
		return "Up"
	case HostStateDown:
		return "Down"
	default:
		return ""
	}
}
