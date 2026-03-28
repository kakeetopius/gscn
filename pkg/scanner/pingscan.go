package scanner

import (
	"net/netip"
	"time"

	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/prometheus-community/pro-bing"
	"github.com/pterm/pterm"
)

type PingScanOptions struct {
	Targets     []netip.Prefix
	PingTimeout time.Duration
	workers     int
	timeout     time.Duration
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
	opts            PingScanOptions
	results         PingScanResults
	stats           PingStats
	messageNotifier notifier.Notifier
}

func NewPingScanner(opts PingScanOptions) Scanner {
	return &PingScanner{
		opts: opts,
		results: PingScanResults{
			ResultMap: make(map[netip.Addr]HostState),
		},
		stats: PingStats{},
	}
}

func (s *PingScanner) WithTargets(t []netip.Prefix) Scanner {
	s.opts.Targets = t
	return s
}

func (s *PingScanner) WithWorkers(w int) Scanner {
	s.opts.workers = w
	return s
}

func (s *PingScanner) WithTimeout(d time.Duration) Scanner {
	s.opts.timeout = d
	return s
}

func (s *PingScanner) WithHostNames(_ map[netip.Addr]string, _ bool) Scanner {
	return s
}

func (s *PingScanner) WithVendorInfo() Scanner {
	return s
}

func (s *PingScanner) WithNotifier(n notifier.Notifier) Scanner {
	s.messageNotifier = n
	return s
}

func (s *PingScanner) Scan() error {
	err := PingHosts(s, s.opts.Targets)
	return err
}

func (s *PingScanner) Results() ScanResults {
	return s.results
}

func (s *PingScanner) SendResultsViaNotifier() error {
	if s.messageNotifier == nil {
		return nil
	}
	spinner, err := pterm.DefaultSpinner.Start("Sending Results....")
	if err != nil {
		return err
	}
	defer spinner.Stop()

	return s.messageNotifier.SendMessage(s.results.String())
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
			pinger.Timeout = scanner.opts.PingTimeout

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
