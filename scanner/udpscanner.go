package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/kakeetopius/gscn/internal/log"
	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/pterm/pterm"
)

type UDPScanner struct {
	UDPScanOptions

	results    UDPScanResults
	hostStates PingScanResultsMap
	logger     log.Logger
}

type UDPScanOptions struct {
	Targets             []netip.Prefix
	TargetPorts         []PortNumber
	Workers             int
	PingTimeout         time.Duration
	PingCount           int
	ResponseTimeout     time.Duration
	HostNames           map[netip.Addr]string
	AddUnknownHostNames bool

	PrintUpOnly   bool
	PrintOpenOnly bool
}

type UDPScanResults struct {
	Results HostResults  `json:"results"`
	Stats   UDPScanStats `json:"stats"`

	printUpOnly   bool `json:"-"`
	printOpenOnly bool `json:"-"`
}

type UDPScanStats struct {
	TotalNumOfHosts int           `json:"total_scanned"`
	ScanTime        time.Duration `json:"scan_duration"`
}

func NewUDPScanner(opts UDPScanOptions) *UDPScanner {
	if opts.HostNames == nil {
		opts.HostNames = make(map[netip.Addr]string)
	}
	return &UDPScanner{
		UDPScanOptions: opts,
		results: UDPScanResults{
			Results: make(HostResults),
		},
		logger: log.NewLogger(true),
	}
}

func (s *UDPScanner) Scan(ctx context.Context) (ScanResults, error) {
	startTime := time.Now()
	err := s.runUDPScan(ctx)
	if err != nil {
		return nil, err
	}

	s.results.Stats.ScanTime = time.Since(startTime)
	s.results.Stats.TotalNumOfHosts = len(s.results.Results)
	s.results.printOpenOnly = s.PrintOpenOnly
	s.results.printUpOnly = s.PrintUpOnly

	s.processResults()
	return &s.results, nil
}

func (s *UDPScanner) processResults() {
	if s.AddUnknownHostNames {
		spinner, _ := pterm.DefaultSpinner.Start("Resolving Host Names....")
		defer spinner.Success("Resolving Done")
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

func (r *UDPScanResults) Print() {
	printScanResultsMap(r.Results, r.Stats.ScanTime, r.printUpOnly, r.printOpenOnly)
}

func (r *UDPScanResults) String() string {
	stringBuilder := strings.Builder{}

	hostTmpl := template.Must(template.New("host_result").Parse(HostResultTemplate))
	tmpl := template.Must(hostTmpl.New("udp_full_scan").Parse(UDPScanResultsTemplate))

	tmpl.Execute(&stringBuilder, r)
	return stringBuilder.String()
}

func (s *UDPScanner) runUDPScan(ctx context.Context) error {
	if s.Workers <= 0 {
		return fmt.Errorf("invalid number of workers")
	}
	numWorkers := s.Workers

	pterm.Warning.Println("UDP Scans are not reliable and may show inconsistent or wrong results.")
	if len(s.Targets) == 0 {
		return fmt.Errorf("no hosts to scan provided")
	}
	if len(s.TargetPorts) == 0 {
		s.TargetPorts = CommonPorts
	}

	pingResults, err := pingHosts(ctx, s.Targets, s.PingTimeout, int(s.Workers), s.PingCount) // first check if hosts are up.
	if err != nil {
		return err
	}
	s.hostStates = pingResults
	s.results.Results = getResultSet(s.Targets, s.TargetPorts, s.HostNames, s.hostStates, "udp")

	jobs := make(chan PortScanJob, numWorkers)
	workerResultsChan := make(chan PortScanWorkerResult, numWorkers)
	wg := &sync.WaitGroup{}
	for range numWorkers {
		wg.Add(1)
		go scanUDPPort(s, wg, jobs, workerResultsChan)
	}

	spinner, err := pterm.DefaultSpinner.Start("Scanning hosts")
	if err != nil {
		return err
	}
	defer spinner.Success("Scanning Done")

	masterDone := make(chan struct{})
	go s.getUDPScanResults(ctx, workerResultsChan, masterDone)

	sendPortScanningJobs(ctx, jobs, s.Targets, s.TargetPorts, s.ResponseTimeout)

	close(jobs) // wait for all the workers to finish
	wg.Wait()

	<-time.After(s.ResponseTimeout) // wait for the specified response timeout

	close(workerResultsChan)
	<-masterDone // wait for master to process all data in workerResultsChan
	close(masterDone)

	return nil
}

func scanUDPPort(scanner *UDPScanner, wg *sync.WaitGroup, jobs chan PortScanJob, resultsChan chan<- PortScanWorkerResult) {
	defer func() {
		wg.Done()
	}()

	for job := range jobs {
		target := job.target
		proto := ""
		if target.Addr().Is4() {
			proto = "udp"
		} else {
			proto = "udp6"
		}
		result := PortScanWorkerResult{
			HostIP: target.Addr(),
			Port: Port{
				State:  PortStateClosed,
				Number: PortNumber(target.Port()),
			},
		}
		if scanner.hostStates[target.Addr()].HostState == HostStateDown {
			resultsChan <- result
			continue
		}

		dialer := net.Dialer{
			Timeout: job.scanTimeout,
		}
		conn, err := dialer.Dial(proto, target.String())
		if err != nil {
			resultsChan <- result
			continue
		}

		err = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err != nil {
			resultsChan <- result
			continue
		}
		buf := make([]byte, 1)
		conn.Write(buf) // first write to the connection so we can get responses if any
		_, err = conn.Read(buf)
		if err != nil {
			// Here we assume that if the read attempt on the socket timed out then the port is open
			if errors.Is(err, os.ErrDeadlineExceeded) {
				result.Port.State = PortStatePossibleFilter
			} else {
				// any other error means the port is closed
				result.Port.State = PortStateClosed
			}
		} else {
			result.Port.State = PortStateOpen
		}

		resultsChan <- result
	}
}

func (s *UDPScanner) getUDPScanResults(ctx context.Context, workerResultsChan chan PortScanWorkerResult, masterDone chan<- struct{}) {
	// To Be Run By Main Worker
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
			if !ok {
				return
			}

			hostIP := result.HostIP

			hostResult := s.results.Results[hostIP]
			portIndex := hostResult.portIndex[result.Port.Number]
			hostResult.Ports[portIndex].State = result.Port.State

			switch result.Port.State {
			case PortStateOpen:
				hostResult.HostState = HostStateUp // sometimes ping scan failed but port scan succeeds so if port is open then host is up.
				hostResult.OpenPorts++
				hostResult.ClosedPorts--
			case PortStatePossibleFilter:
				hostResult.FilteredPorts++
				hostResult.ClosedPorts--
			}

			s.results.Results[hostIP] = hostResult
		}
	}
}
