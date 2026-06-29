package scanner

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/log"
	"github.com/kakeetopius/gscn/internal/notify"
	"github.com/kakeetopius/gscn/internal/util"
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
	TargetPorts         []uint
	Workers             int
	PingCount           int
	ResponseTimeout     time.Duration
	HostNames           map[netip.Addr]string
	AddUnknownHostNames bool
	PingTimeout         time.Duration
	SkipPingScan        bool
	MessageNotifier     notify.Notifier

	PrintUpOnly   bool
	PrintOpenOnly bool
}

type TCPFullScanResults struct {
	HostResults      `json:"results"`
	TCPFullScanStats `json:"stats"`
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
			HostResults: make(HostResults),
		},
		logger: log.NewLogger(true),
	}
}

func (s *TCPFullScanner) SendResultsViaNotifier() error {
	if s.MessageNotifier == nil {
		return fmt.Errorf("tcpfullscanner: no notifier is set")
	}
	spinner, err := pterm.DefaultSpinner.Start("Sending Results....")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			spinner.Fail()
		} else {
			spinner.Success("Results Sent")
		}
	}()

	err = s.MessageNotifier.SendMessage(s.results.String())
	if err != nil {
		return err
	}

	return nil
}

func (s *TCPFullScanner) Scan() error {
	startTime := time.Now()
	hostResults, err := s.runTCPFullScan()
	if err != nil {
		return err
	}
	stopTime := time.Now()

	s.results.HostResults = hostResults
	s.results.ScanTime = stopTime.Sub(startTime)

	s.addResultsInfo()
	return nil
}

func (s *TCPFullScanner) Results() ScanResults {
	return s.results
}

func (s *TCPFullScanner) PrintResults() {
	printScanResultsMap(s.results.HostResults, s.results.ScanTime, s.PrintUpOnly, s.PrintOpenOnly)
}

func (s *TCPFullScanner) SetNotifier(n notify.Notifier) {
	s.MessageNotifier = n
}

func (s *TCPFullScanner) addResultsInfo() {
	if s.AddUnknownHostNames {
		spinner, _ := pterm.DefaultSpinner.Start("Resolving Host Names....")
		defer spinner.Success("Resolving done")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		for host, results := range s.results.HostResults {
			if results.HostName != "" {
				continue
			}
			name := util.ReverseLookup(ctx, host.String())
			results.HostName = name
			s.results.HostResults[host] = results
		}
	}

	for _, hostResult := range s.results.HostResults {
		slices.SortFunc(hostResult.Ports, func(a, b Port) int {
			return int(a.Number - b.Number)
		})
	}
}

func (r TCPFullScanResults) String() string {
	stringBuilder := strings.Builder{}

	hostTmpl := template.Must(template.New("host_result").Parse(HostResultTemplate))
	tmpl := template.Must(hostTmpl.New("tcp_full_scan").Parse(TCPFullScanResultsTemplate))

	tmpl.Execute(&stringBuilder, r)
	return stringBuilder.String()
}

func (s *TCPFullScanner) runTCPFullScan() (HostResults, error) {
	opts := s.TCPFullScanOptions
	targets := opts.Targets
	ports := opts.TargetPorts

	numWorkers := opts.Workers

	if len(targets) == 0 {
		return HostResults{}, fmt.Errorf("no hosts to scan provided")
	}
	if len(ports) == 0 {
		return HostResults{}, fmt.Errorf("no ports provided for scanning")
	}

	if !opts.SkipPingScan {
		pingResults, err := pingHosts(targets, opts.PingTimeout, int(opts.Workers), opts.PingCount) // first check if hosts are up.
		if err != nil {
			return HostResults{}, err
		}
		s.hostStates = pingResults
	}
	jobs := make(chan PortScanJob, numWorkers)
	workerResultsChan := make(chan PortScanWorkerResult, numWorkers)
	wg := &sync.WaitGroup{}
	for range numWorkers {
		wg.Add(1)
		go scanTCPPort(wg, jobs, workerResultsChan)
	}

	spinner, err := pterm.DefaultSpinner.Start("Scanning hosts")
	if err != nil {
		return HostResults{}, err
	}
	defer spinner.Success("Scanning Done")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	senderDone := make(chan struct{})

	go sendPortScanningJobs(ctx, senderDone, jobs, opts.Targets, opts.TargetPorts, opts.ResponseTimeout)

	scanResultsChan := make(chan HostResults)
	go getTCPFullScanResults(ctx, s, workerResultsChan, scanResultsChan)

	<-senderDone // wait for sender to send all jobs

	close(jobs) // wait for all to workers to finish
	wg.Wait()

	close(workerResultsChan) // tell main worker to stop

	scanResults := <-scanResultsChan
	return scanResults, nil
}

func getTCPFullScanResults(ctx context.Context, scanner *TCPFullScanner, workerResultsChan chan PortScanWorkerResult, scanResultsChan chan HostResults) {
	// To Be Run By Main Worker (aggregator)
	scanResults := make(HostResults)
	numberOfPortsToScan := len(scanner.TargetPorts)

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
			hostIP := result.HostIP
			hostResult, found := scanResults[hostIP]
			if !found {
				hostResult.Addr = hostIP
				hostResult.Ports = make([]Port, 0, numberOfPortsToScan)
				hostResult.HostName = scanner.HostNames[hostIP]             // get hostname from scanner options
				hostResult.HostState = scanner.hostStates[hostIP].HostState // get hostState from scanner options
				hostResult.AverageRTT = scanner.hostStates[hostIP].AverageRTT

				scanner.results.TotalNumOfHosts++
			}
			hostResult.Ports = append(hostResult.Ports, result.Port)
			switch result.Port.State {
			case PortStateOpen:
				hostResult.HostState = HostStateUp // sometimes ping scan failed but port scan succeeds so if port is open then host is up.
				hostResult.OpenPorts++
			case PortStateClosed:
				hostResult.ClosedPorts++
			}
			scanResults[hostIP] = hostResult
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
				Number:   uint(target.Port()),
				Protocol: proto,
			},
		}
		if err != nil {
			result.Port.State = PortStateClosed
		} else {
			result.Port.State = PortStateOpen
			result.Port.Name = util.Service(layers.TCPPort(target.Port()).String())
		}

		resultsChan <- result
	}
}
