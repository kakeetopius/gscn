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

	PrintUpOnly   bool
	PrintOpenOnly bool
}

type TCPFullScanResults struct {
	Results HostResults      `json:"results"`
	Stats   TCPFullScanStats `json:"stats"`

	printUpOnly   bool `json:"-"`
	printOpenOnly bool `json:"-"`
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
	stopTime := time.Now()

	s.results.Stats.ScanTime = stopTime.Sub(startTime)
	s.results.Stats.TotalNumOfHosts = len(s.results.Results)
	s.results.printOpenOnly = s.PrintOpenOnly
	s.results.printUpOnly = s.PrintUpOnly

	s.addResultsInfo()
	return &s.results, nil
}

func (s *TCPFullScanner) addResultsInfo() {
	if s.AddUnknownHostNames {
		spinner, _ := pterm.DefaultSpinner.Start("Resolving Host Names....")
		defer spinner.Success("Resolving done")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		for host, results := range s.results.Results {
			if results.HostName != "" {
				continue
			}
			name := netutil.ReverseLookup(ctx, host.String())
			results.HostName = name
			s.results.Results[host] = results
		}
	}
}

func (r *TCPFullScanResults) Print() {
	printScanResultsMap(r.Results, r.Stats.ScanTime, r.printUpOnly, r.printOpenOnly)
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
	}
	s.results.Results = getResultSet(s.Targets, s.TargetPorts, s.HostNames, s.hostStates, "tcp")

	jobs := make(chan PortScanJob, numWorkers)
	workerResultsChan := make(chan PortScanWorkerResult, numWorkers)
	wg := &sync.WaitGroup{}

	for range numWorkers {
		wg.Add(1)
		go scanTCPPort(wg, jobs, workerResultsChan)
	}

	spinner, err := pterm.DefaultSpinner.Start("Scanning hosts")
	if err != nil {
		return err
	}
	defer spinner.Success("Scanning Done")

	masterDone := make(chan struct{})
	go s.getTCPFullScanResults(ctx, workerResultsChan, masterDone)

	sendPortScanningJobs(ctx, jobs, s.Targets, s.TargetPorts, s.ResponseTimeout)

	close(jobs)
	wg.Wait() // wait for all to workers to finish

	<-time.After(s.ResponseTimeout) // wait for the specified response timeout

	close(workerResultsChan)
	<-masterDone // wait for master to process all data in the workerResultsChan
	close(masterDone)

	return nil
}

func (s *TCPFullScanner) getTCPFullScanResults(ctx context.Context, workerResultsChan chan PortScanWorkerResult, masterDone chan<- struct{}) {
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

				hostResult.HostState = HostStateUp // sometimes ping scan failed but port scan succeeds so if port is open then host is up.
				hostResult.OpenPorts++
				hostResult.ClosedPorts--
			}

			s.results.Results[hostIP] = hostResult
		}
	}
}

func scanTCPPort(wg *sync.WaitGroup, jobs chan PortScanJob, resultsChan chan<- PortScanWorkerResult) {
	defer func() {
		wg.Done()
	}()

	for job := range jobs {
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
		_, err := dialer.Dial(proto, target.String())

		result := PortScanWorkerResult{
			HostIP: target.Addr(),
			Port: Port{
				State:  PortStateClosed,
				Number: PortNumber(target.Port()),
			},
		}
		if err == nil {
			result.Port.State = PortStateOpen
		}

		resultsChan <- result
	}
}
