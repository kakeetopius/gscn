package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/kakeetopius/gscn/internal/log"
	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/pterm/pterm"
)

type TCPFullScanner struct {
	TCPFullScanOptions

	results    TCPFullScanResults
	hostStates PingScanResultsMap
	logger     log.Logger
}

type TCPFullScanOptions struct {
	Targets             []netip.Prefix
	TargetPorts         []PortNumber
	Workers             int
	PingCount           int
	ResponseTimeout     time.Duration
	HostNames           map[netip.Addr]string
	AddUnknownHostNames bool
	PingTimeout         time.Duration
	SkipPingScan        bool
	Banners             bool

	PrintUpOnly   bool
	PrintOpenOnly bool
}

type TCPFullScanResults struct {
	Results HostResults      `json:"results"`
	Stats   TCPFullScanStats `json:"stats"`

	printUpOnly   bool `json:"-"`
	printOpenOnly bool `json:"-"`
	printBanners  bool `json:"-"`
}

type TCPFullScanStats struct {
	TotalNumOfHosts int           `json:"total_scanned"`
	ScanTime        time.Duration `json:"scan_duration"`
}

func NewTCPFullScanner(opts TCPFullScanOptions) *TCPFullScanner {
	if opts.HostNames == nil {
		opts.HostNames = make(map[netip.Addr]string)
	}
	return &TCPFullScanner{
		TCPFullScanOptions: opts,
		results: TCPFullScanResults{
			Results: make(HostResults),
		},
		logger: log.NewLogger(true),
	}
}

func (s *TCPFullScanner) Scan(ctx context.Context) (ScanResults, error) {
	startTime := time.Now()
	err := s.runTCPFullScan(ctx)
	if err != nil {
		return nil, err
	}

	s.results.Stats.ScanTime = time.Since(startTime)
	s.results.Stats.TotalNumOfHosts = len(s.results.Results)
	s.results.printOpenOnly = s.PrintOpenOnly
	s.results.printBanners = s.Banners
	s.results.printUpOnly = s.PrintUpOnly

	s.processResults(ctx)
	return &s.results, nil
}

func (s *TCPFullScanner) processResults(ctx context.Context) {
	if ctx.Err() != nil { // we have already been cancelled
		return
	}
	if !s.AddUnknownHostNames {
		return
	}
	spinner, _ := pterm.DefaultSpinner.Start("Resolving Host Names....")
	newCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	defer func() {
		if ctx.Err() != nil {
			spinner.Fail("Resolving Cancelled.")
		} else {
			spinner.Success("Resolving done")
		}
	}()

	for host, results := range s.results.Results {
		if ctx.Err() != nil {
			return
		}
		if results.HostName != "" {
			continue
		}
		name := netutil.ReverseLookup(newCtx, host.String())
		results.HostName = name
		s.results.Results[host] = results
	}
}

func (r *TCPFullScanResults) Print() {
	printScanResultsMap(r.Results, r.Stats.ScanTime, r.printUpOnly, r.printOpenOnly, r.printBanners)
}

func (r *TCPFullScanResults) String() string {
	stringBuilder := strings.Builder{}

	hostTmpl := template.Must(template.New("host_result").Parse(HostResultTemplate))
	tmpl := template.Must(hostTmpl.New("tcp_full_scan").Parse(TCPFullScanResultsTemplate))

	tmpl.Execute(&stringBuilder, r)
	return stringBuilder.String()
}

func (s *TCPFullScanner) runTCPFullScan(ctx context.Context) error {
	if s.Workers <= 0 {
		return fmt.Errorf("invalid number of workers")
	}
	numWorkers := s.Workers

	if len(s.Targets) == 0 {
		return fmt.Errorf("no hosts to scan provided")
	}
	if len(s.TargetPorts) == 0 {
		s.TargetPorts = CommonPorts
	}

	if !s.SkipPingScan {
		pingResults, err := pingHosts(ctx, s.Targets, s.PingTimeout, int(s.Workers), s.PingCount) // first check if hosts are up.
		if err != nil {
			return err
		}
		s.hostStates = pingResults
		if ctx.Err() != nil { // we have already been cancelled
			return nil
		}
	}
	s.results.Results = getResultSet(s.Targets, s.TargetPorts, s.HostNames, s.hostStates, "tcp")

	jobs := make(chan portScanJob, numWorkers)
	workerResultsChan := make(chan portScanWorkerResult, numWorkers)
	wg := &sync.WaitGroup{}

	for range numWorkers {
		wg.Add(1)
		go scanTCPPort(ctx, wg, jobs, workerResultsChan, s.Banners)
	}

	spinner, err := pterm.DefaultSpinner.Start("Scanning hosts")
	if err != nil {
		return err
	}

	masterDone := make(chan struct{})
	go s.getTCPFullScanResults(ctx, workerResultsChan, masterDone)

	sendPortScanningJobs(ctx, jobs, s.Targets, s.TargetPorts, s.HostNames, s.ResponseTimeout)

	if ctx.Err() != nil {
		spinner.Fail("Scan Cancelled")
		return nil
	}

	close(jobs)
	wg.Wait() // wait for all to workers to finish
	if ctx.Err() != nil {
		spinner.Fail("Scan Cancelled")
		return nil
	}
	spinner.Success("Scanning Done")

	s.logger.WaitTimeout(ctx, s.ResponseTimeout, "response") // wait for the response timeout

	close(workerResultsChan)
	<-masterDone // wait for master to process all data in the workerResultsChan
	close(masterDone)

	return nil
}

func (s *TCPFullScanner) getTCPFullScanResults(ctx context.Context, workerResultsChan chan portScanWorkerResult, masterDone chan<- struct{}) {
	// To Be Run By Main Worker (aggregator)
	defer func() {
		masterDone <- struct{}{}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-workerResultsChan:
			if !ok {
				return
			}

			hostIP := result.HostIP

			hostResult := s.results.Results[hostIP]

			if result.Port.State == PortStateOpen {
				portIndex := hostResult.portIndex[result.Port.Number]
				hostResult.Ports[portIndex].State = PortStateOpen
				hostResult.Ports[portIndex].Banner = result.Banner

				hostResult.HostState = HostStateUp // sometimes ping scan failed but port scan succeeds so if port is open then host is up.
				hostResult.OpenPorts++
				hostResult.ClosedPorts--
			}

			s.results.Results[hostIP] = hostResult
		}
	}
}

func scanTCPPort(
	ctx context.Context,
	wg *sync.WaitGroup,
	jobs chan portScanJob,
	resultsChan chan<- portScanWorkerResult,
	try2GetBanners bool,
) {
	defer func() {
		wg.Done()
	}()

	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		proto := ""
		target := job.target
		if target.Addr().Is4() {
			proto = "tcp"
		} else {
			proto = "tcp6"
		}
		dialer := net.Dialer{
			Timeout: job.scanTimeout,
		}

		func() {
			port := target.Port()
			result := portScanWorkerResult{
				HostIP: target.Addr(),
				Port: Port{
					State:  PortStateClosed,
					Number: PortNumber(port),
				},
			}
			defer func() {
				resultsChan <- result
			}()

			conn, err := dialer.DialContext(ctx, proto, target.String())
			if err != nil {
				return
			}
			defer conn.Close()

			result.Port.State = PortStateOpen
			if !try2GetBanners {
				return
			}

			prober, found := Probers[PortNumber(port)]
			if !found {
				return
			}

			banner, err := prober(conn, job)
			if err != nil {
				fmt.Println(err)
				return
			}
			result.Banner = banner

			fmt.Printf("Probing Port %v\n", port)
			fmt.Println(result.Banner)
		}()

	}
}
