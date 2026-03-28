package scanner

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/prometheus-community/pro-bing"
	"github.com/pterm/pterm"
)

type PingScanOptions struct {
	Targets             []netip.Prefix
	PingTimeout         time.Duration
	Workers             int
	AddUnknownHostNames bool
	HostNames           map[netip.Addr]string
	MessageNotifier     notifier.Notifier
}

type PingResult struct {
	HostState
	HostName string
}

type PingScanResults struct {
	ResultMap map[netip.Addr]PingResult
}

func (r PingScanResults) String() string {
	stringBuilder := strings.Builder{}
	fmt.Fprintf(&stringBuilder, "Ping Scan Results.\n\n")
	for addr, result := range r.ResultMap {
		fmt.Fprintf(&stringBuilder, "%v", addr.String())
		if result.HostName != "" {
			fmt.Fprintf(&stringBuilder, " (%v)", result.HostName)
		}
		fmt.Fprintf(&stringBuilder, "->\t%v\n", result.String())
	}
	return stringBuilder.String()
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
			ResultMap: make(map[netip.Addr]PingResult),
		},
		stats: PingStats{},
	}
}

func (s *PingScanner) Scan() error {
	err := runPing(s, s.Targets)
	return err
}

func (s *PingScanner) Results() ScanResults {
	if s.AddUnknownHostNames {
		spinner, _ := pterm.DefaultSpinner.Start("Resolving Host Names....")
		defer spinner.Stop()
		for host, results := range s.results.ResultMap {
			if results.HostName != "" {
				continue
			}
			name := ReverseLookup(host.String(), 2*time.Second)
			results.HostName = name
			s.results.ResultMap[host] = results
		}
	}
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

func runPing(scanner *PingScanner, targets []netip.Prefix) error {
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
				scanner.results.ResultMap[IPaddr] = PingResult{
					HostState: HostStateUp,
					HostName:  scanner.HostNames[IPaddr],
				}
			} else {
				scanner.results.ResultMap[IPaddr] = PingResult{
					HostState: HostStateDown,
					HostName:  scanner.HostNames[IPaddr],
				}
			}
			IPaddr = IPaddr.Next()
		}
	}
	return nil
}
