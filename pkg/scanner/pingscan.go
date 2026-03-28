package scanner

import (
	"net/netip"
	"time"

	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/prometheus-community/pro-bing"
	"github.com/pterm/pterm"
)

type PingScanOptions struct {
	Targets         []netip.Prefix
	PingTimeout     time.Duration
	Workers         int
	HostNames       map[netip.Addr]string
	MessageNotifier notifier.Notifier
}

type PingScanResults struct {
	ResultMap map[netip.Addr]HostState
}

func (r PingScanResults) String() string {
	return ""
}

func (r PingScanResults) ResultType() ScanResultType {
	return PingScanResultType
}

type PingStats struct{}

type PingScanner struct {
	PingScanOptions
	results PingScanResults
	stats   PingStats
}

func NewPingScanner(opts PingScanOptions) *PingScanner {
	if opts.HostNames == nil {
		opts.HostNames = make(map[netip.Addr]string)
	}
	return &PingScanner{
		PingScanOptions: opts,
		results: PingScanResults{
			ResultMap: make(map[netip.Addr]HostState),
		},
		stats: PingStats{},
	}
}

func (s *PingScanner) Scan() error {
	err := PingHosts(s, s.Targets)
	return err
}

func (s *PingScanner) Results() ScanResults {
	return s.results
}

func (s *PingScanner) SendResultsViaNotifier() error {
	if s.MessageNotifier == nil {
		return nil
	}
	spinner, err := pterm.DefaultSpinner.Start("Sending Results....")
	if err != nil {
		return err
	}
	defer spinner.Stop()

	return s.MessageNotifier.SendMessage(s.results.String())
}

func (s *PingScanner) Stats() ScanStats {
	return s.stats
}

func PingHosts(scanner *PingScanner, targets []netip.Prefix) error {
	spinner, err := pterm.DefaultSpinner.Start("Pinging Hosts")
	if err != nil {
		return err
	}
	defer spinner.Stop()

	for _, target := range targets {
		IPaddr := target.Masked().Addr() // first IP in range
		for target.Contains(IPaddr) {
			pinger := probing.New(IPaddr.String())
			pinger.SetPrivileged(true)
			pinger.Count = 1
			pinger.Timeout = scanner.PingTimeout

			err := pinger.Run()
			if err != nil {
				return err
			}
			stats := pinger.Statistics()
			if stats.PacketsRecv > 0 {
				scanner.results.ResultMap[IPaddr] = HostStateUp
			} else {
				scanner.results.ResultMap[IPaddr] = HostStateDown
			}
			IPaddr = IPaddr.Next()
		}
	}
	return nil
}
