// Package scanner provides functionality for scanning network devices using various network protocols,
// including ARP, NDP, TCP, UDP.
package scanner

import (
	"net"
	"net/netip"
	"time"
)

type Interface struct {
	*net.Interface
}

type ScanResults interface {
	ResultType() ScanResultType
}

type ScanStats any

type Scanner interface {
	Scan() error
	Results() ScanResults
	Stats() ScanStats
	WithTimeout(d time.Duration) Scanner
	WithHostNames(known map[netip.Addr]string, addUnknown bool) Scanner
	WithVendorInfo() Scanner
	WithWorkers(w int) Scanner
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
