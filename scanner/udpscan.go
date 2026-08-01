package scanner

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
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
	HostResults  `json:"results"`
	UDPScanStats `json:"stats"`

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
			HostResults: make(HostResults),
		},
		logger: log.NewLogger(true),
	}
}

func (s *UDPScanner) Scan() (ScanResults, error) {
	startTime := time.Now()
	err := s.runUDPScan()
	if err != nil {
		return nil, err
	}
	stopTime := time.Now()

	s.results.ScanTime = stopTime.Sub(startTime)
	s.results.printOpenOnly = s.PrintOpenOnly
	s.results.printUpOnly = s.PrintUpOnly

	s.addResultsInfo()
	return &s.results, nil
}

func (s *UDPScanner) addResultsInfo() {
	if s.AddUnknownHostNames {
		spinner, _ := pterm.DefaultSpinner.Start("Resolving Host Names....")
		defer spinner.Success("Resolving Done")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for host, results := range s.results.HostResults {
			if results.HostName != "" {
				continue
			}
			name := netutil.ReverseLookup(ctx, host.String())
			results.HostName = name
			s.results.HostResults[host] = results
		}
	}
}

func (r *UDPScanResults) Print() {
	printScanResultsMap(r.HostResults, r.ScanTime, r.printUpOnly, r.printOpenOnly)
}

func (r *UDPScanResults) String() string {
	stringBuilder := strings.Builder{}

	hostTmpl := template.Must(template.New("host_result").Parse(HostResultTemplate))
	tmpl := template.Must(hostTmpl.New("udp_full_scan").Parse(UDPScanResultsTemplate))

	tmpl.Execute(&stringBuilder, r)
	return stringBuilder.String()
}

func (s *UDPScanner) runUDPScan() error {
	numWorkers := s.Workers

	pterm.Warning.Println("UDP Scans are not reliable and may show inconsistent or wrong results.")
	if len(s.Targets) == 0 {
		return fmt.Errorf("no hosts to scan provided")
	}
	if len(s.TargetPorts) == 0 {
		s.TargetPorts = CommonPorts
	}

	pingResults, err := pingHosts(s.Targets, s.PingTimeout, int(s.Workers), s.PingCount) // first check if hosts are up.
	if err != nil {
		return err
	}
	s.hostStates = pingResults
	s.results.HostResults = getResultSet(s.Targets, s.TargetPorts, s.HostNames, s.hostStates, "udp")

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	senderDone := make(chan struct{})

	go sendPortScanningJobs(ctx, senderDone, jobs, s.Targets, s.TargetPorts, s.ResponseTimeout)

	go s.getUDPScanResults(ctx, workerResultsChan)

	<-senderDone // wait for sender to send all jobs

	close(jobs) // wait for all the workers to finish
	wg.Wait()

	close(workerResultsChan) // tell the main Woker to stop

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
				Number:   PortNumber(target.Port()),
				Protocol: proto,
			},
		}
		if scanner.hostStates[target.Addr()].HostState == HostStateDown {
			result.Port.State = PortStateClosed
			resultsChan <- result
			continue
		}

		dialer := net.Dialer{
			Timeout: job.scanTimeout,
		}
		conn, err := dialer.Dial(proto, target.String())
		if err != nil {
			result.Port.State = PortStateClosed
			resultsChan <- result
			continue
		}

		err = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err != nil {
			result.Port.State = PortStateClosed
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
				result.Port.Name = netutil.Service(layers.UDPPort(target.Port()).String())
			} else {
				// any other error means the port is closed
				result.Port.State = PortStateClosed
			}
		} else {
			result.Port.State = PortStateOpen
			result.Port.Name = netutil.Service(layers.UDPPort(target.Port()).String())
		}

		resultsChan <- result
	}
}

func (s *UDPScanner) getUDPScanResults(ctx context.Context, workerResultsChan chan PortScanWorkerResult) {
	// To Be Run By Main Worker
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

			hostResult := s.results.HostResults[hostIP]
			portIndex := hostResult.portIndex[result.Port.Number]
			hostResult.Ports[portIndex] = result.Port

			switch result.Port.State {
			case PortStateOpen:
				hostResult.HostState = HostStateUp // sometimes ping scan failed but port scan succeeds so if port is open then host is up.
				hostResult.OpenPorts++
			case PortStateClosed:
				hostResult.ClosedPorts++
			case PortStatePossibleFilter:
				hostResult.FilteredPorts++
			}

			s.results.HostResults[hostIP] = hostResult
		}
	}
}
