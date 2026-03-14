// Package scanner provides functionality for scanning network devices and protocols,
// including ARP, NDP etc.
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
	TCPScanResultType
	UDPScanResultType
)
