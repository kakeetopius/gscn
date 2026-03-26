// Package scanner provides functionality for scanning network devices using various network protocols,
// including ARP, NDP, TCP, UDP.
package scanner

import (
	"net/netip"
	"time"

	"github.com/kakeetopius/gscn/internal/notifier"
)

type ScanResults interface {
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
	// WithTimeout sets a timeout duration for the scan and returns the Scanner for method chaining.
	WithTimeout(d time.Duration) Scanner
	// WithHostNames sets known hostname mappings for IP addresses and controls whether to add unknown hostnames.
	WithHostNames(known map[netip.Addr]string, addUnknown bool) Scanner
	// WithVendorInfo enables vendor information retrieval during the scan.
	WithVendorInfo() Scanner
	// WithWorkers sets the number of concurrent workers for the scan.
	WithWorkers(w int) Scanner
	// WithNotifier sets which notifier to use to send scan results
	WithNotifier(notifier.Notifier) Scanner
}

type ScanResultType int

const (
	ARPScanResultType ScanResultType = iota
	NDPScanResultType
	TCPFullScanScanResultType
	UDPScanResultType
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

type Port struct {
	Number   uint
	Name     string
	Protocol string
	State    PortState
}

// HostResult is the result of a single host after port scanning
type HostResult struct {
	Ports       map[uint]Port
	HostName    string
	OpenPorts   int
	ClosedPorts int
}
