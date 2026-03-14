// Package scanner provides functionality for scanning network devices using various network protocols,
// including ARP, NDP, TCP, UDP.
package scanner

import (
	"io"
	"net"
	"time"
)

type generalScanOptions struct {
	Logger  io.Writer
	Timeout time.Duration
}

type IfaceOpts struct {
	*net.Interface
}

type ScanOptions any

type ScanResults interface {
	ResultType() ScanResultType
}

type ScanStats any

type Scanner interface {
	Scan(opts *ScanOptions) error
	Results() ScanResults
	Stats() ScanStats
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
