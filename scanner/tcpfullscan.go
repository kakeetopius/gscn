package scanner

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
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

func (s *TCPFullScanner) Scan() (ScanResults, error) {
	startTime := time.Now()
	err := s.runTCPFullScan()
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

func (s *TCPFullScanner) runTCPFullScan() error {
	numWorkers := s.Workers

	if len(s.Targets) == 0 {
		return fmt.Errorf("no hosts to scan provided")
	}
	if len(s.TargetPorts) == 0 {
		s.TargetPorts = CommonPorts
	}

	if !s.SkipPingScan {
		pingResults, err := pingHosts(s.Targets, s.PingTimeout, int(s.Workers), s.PingCount) // first check if hosts are up.
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	senderDone := make(chan struct{})

	go sendPortScanningJobs(ctx, senderDone, jobs, s.Targets, s.TargetPorts, s.ResponseTimeout)

	go s.getTCPFullScanResults(ctx, workerResultsChan)

	<-senderDone // wait for sender to send all jobs

	close(jobs) // wait for all to workers to finish
	wg.Wait()

	close(workerResultsChan) // tell main worker to stop

	return nil
}

func (s *TCPFullScanner) getTCPFullScanResults(ctx context.Context, workerResultsChan chan PortScanWorkerResult) {
	// To Be Run By Main Worker (aggregator)
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
			portIndex := hostResult.portIndex[result.Port.Number]
			hostResult.Ports[portIndex] = result.Port

			switch result.Port.State {
			case PortStateOpen:
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
				Number:   PortNumber(target.Port()),
				Protocol: proto,
			},
		}
		if err != nil {
			result.Port.State = PortStateClosed
		} else {
			result.Port.State = PortStateOpen
			result.Port.Name = netutil.Service(layers.TCPPort(target.Port()).String())
		}

		resultsChan <- result
	}
}
