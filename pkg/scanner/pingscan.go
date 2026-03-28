package scanner

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/prometheus-community/pro-bing"
	"github.com/pterm/pterm"
)

type PingScanJob struct {
	Target netip.Addr
}

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
	IP       netip.Addr
	HostName string
}

type PingScanResults struct {
	ResultMap map[netip.Addr]PingResult
}

func (r PingScanResults) String() string {
	stringBuilder := strings.Builder{}
	up := 0
	fmt.Fprintf(&stringBuilder, "Ping Scan Results.\n\n")
	for addr, result := range r.ResultMap {
		if result.HostState == HostStateDown {
			continue
		}
		up++
		fmt.Fprintf(&stringBuilder, "%v", addr.String())
		if result.HostName != "" {
			fmt.Fprintf(&stringBuilder, " (%v)", result.HostName)
		}
		fmt.Fprintf(&stringBuilder, "->\t%v\n", result.String())
	}
	fmt.Fprintf(&stringBuilder, "\nTotal Hosts Scanned: %v\n", len(r.ResultMap))
	fmt.Fprintf(&stringBuilder, "Hosts that are Up: %v\n", up)
	fmt.Fprintf(&stringBuilder, "Hosts that are Down: %v\n", len(r.ResultMap)-up)

	return stringBuilder.String()
}

func (r PingScanResults) ResultType() ScanResultType {
	return PingScanResultType
}

type PingStats struct {
	UpHosts   int
	DownHosts int
}

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

	jobs := make(chan PingScanJob, scanner.Workers)
	workerResultsChan := make(chan PingResult, scanner.Workers)
	wg := &sync.WaitGroup{}
	for range scanner.Workers {
		wg.Add(1)
		go pingScanHost(scanner, wg, jobs, workerResultsChan)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scanResultsChan := make(chan PingScanResults)
	go getPingScanResults(ctx, scanner, workerResultsChan, scanResultsChan)

	// send jobs
	for _, target := range targets {
		IPaddr := target.Masked().Addr() // first IP in range
		for target.Contains(IPaddr) {
			jobs <- PingScanJob{
				Target: IPaddr,
			}
			IPaddr = IPaddr.Next()
		}
	}

	close(jobs)
	wg.Wait()                // wait for all workers to finish
	close(workerResultsChan) // tell main worker to stop

	pingScanResults := <-scanResultsChan
	scanner.results = pingScanResults
	return nil
}

func pingScanHost(scanner *PingScanner, wg *sync.WaitGroup, jobs chan PingScanJob, resultChan chan PingResult) {
	defer wg.Done()

	for job := range jobs {
		pinger := probing.New(job.Target.String())
		pinger.SetPrivileged(true)
		pinger.Count = 1
		pinger.Timeout = scanner.PingTimeout

		err := pinger.Run()
		if err != nil {
			return
		}
		stats := pinger.Statistics()
		pingResult := PingResult{
			HostState: HostStateDown,
			HostName:  scanner.HostNames[job.Target],
			IP:        job.Target,
		}
		if stats.PacketsRecv > 0 {
			pingResult.HostState = HostStateUp
		}
		resultChan <- pingResult
	}
}

func getPingScanResults(ctx context.Context, scanner *PingScanner, workerResultsChan chan PingResult, scanResultsChan chan PingScanResults) {
	// To Be Run By Main Worker
	scanResults := PingScanResults{
		ResultMap: make(map[netip.Addr]PingResult),
	}
	defer func() {
		scanResultsChan <- scanResults
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-workerResultsChan:
			if !ok {
				return
			}
			switch result.HostState {
			case HostStateDown:
				scanner.stats.DownHosts++
			case HostStateUp:
				scanner.stats.UpHosts++
			}
			scanResults.ResultMap[result.IP] = result
		}
	}
}
