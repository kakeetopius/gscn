package scanner

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/pterm/pterm"
)

type UDPScanOptions struct {
	Targets     []netip.Prefix
	TargetPorts []uint
	workers     uint
	logger      io.Writer
	timeout     time.Duration
}

type UDPScanResults struct {
	ResultMap map[netip.Addr]HostResult
}

func (UDPScanResults) ResultType() ScanResultType {
	return UDPScanResultType
}

func (r UDPScanResults) String() string {
	stringBuilder := strings.Builder{}
	fmt.Fprintf(&stringBuilder, "UDP Scan Results.\n\n")
	for host, result := range r.ResultMap {
		fmt.Fprintf(&stringBuilder, "Results for %v", host.String())
		if result.HostName == "" {
			fmt.Fprintf(&stringBuilder, "\n")
		} else {
			fmt.Fprintf(&stringBuilder, " (%v)\n", result.HostName)
		}
		for _, port := range result.Ports {
			if port.State == PortStateOpen {
				fmt.Fprintf(&stringBuilder, "%v/%v (%v) -> Open\n", port.Protocol, port.Number, port.Name)
			}
		}
		fmt.Fprintf(&stringBuilder, "Total Ports Scanned: %v\n", result.ClosedPorts+result.OpenPorts)
		fmt.Fprintf(&stringBuilder, "Open Ports: %v\n", result.OpenPorts)
		fmt.Fprintf(&stringBuilder, "Closed Ports: %v\n\n", result.ClosedPorts)
	}
	return stringBuilder.String()
}

type UDPScanStats struct {
	TotalNumOfHosts int
}

type UDPScanner struct {
	opts                    *UDPScanOptions
	results                 UDPScanResults
	stats                   UDPScanStats
	resolveUnknownHostNames bool
	hostNames               map[netip.Addr]string
	messageNotifier         notifier.Notifier
}

func NewUDPScanner(opts *UDPScanOptions) Scanner {
	resultMap := make(map[netip.Addr]HostResult)
	return &UDPScanner{
		opts: opts,
		results: UDPScanResults{
			ResultMap: resultMap,
		},
		stats:                   UDPScanStats{},
		hostNames:               make(map[netip.Addr]string),
		resolveUnknownHostNames: false,
	}
}

func (s *UDPScanner) WithHostNames(h map[netip.Addr]string, addUnknown bool) Scanner {
	if h != nil {
		maps.Copy(s.hostNames, h)
	}
	if addUnknown {
		s.resolveUnknownHostNames = true
	}
	return s
}

func (s *UDPScanner) WithVendorInfo() Scanner {
	return s
}

func (s *UDPScanner) WithWorkers(numOfWorkers int) Scanner {
	s.opts.workers = uint(numOfWorkers)
	return s
}

func (s *UDPScanner) WithTimeout(timeout time.Duration) Scanner {
	s.opts.timeout = timeout
	return s
}

func (s *UDPScanner) WithNotifier(n notifier.Notifier) Scanner {
	s.messageNotifier = n
	return s
}

func (s *UDPScanner) Scan() error {
	results, err := runUDPScan(s)
	if err != nil {
		return err
	}
	s.results = results
	return nil
}

func (s *UDPScanner) SendResultsViaNotifier() error {
	if s.messageNotifier == nil {
		return nil
	}
	spinner, err := pterm.DefaultSpinner.Start("Sending Results....")
	if err != nil {
		return err
	}
	defer spinner.Stop()

	return s.messageNotifier.SendMessage(s.Results().String())
}

func (s *UDPScanner) Results() ScanResults {
	if s.resolveUnknownHostNames {
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

func (s *UDPScanner) Stats() ScanStats {
	return s.stats
}

func runUDPScan(scanner *UDPScanner) (UDPScanResults, error) {
	opts := scanner.opts
	targets := opts.Targets
	ports := opts.TargetPorts

	numWorkers := opts.workers

	if len(targets) == 0 {
		return UDPScanResults{}, fmt.Errorf("no hosts to scan provided")
	}
	if len(ports) == 0 {
		return UDPScanResults{}, fmt.Errorf("no ports provided for scanning")
	}

	jobs := make(chan PortScanJob, numWorkers)
	workerResultsChan := make(chan PortScanWorkerResult, numWorkers)
	wg := &sync.WaitGroup{}
	for range numWorkers {
		wg.Add(1)
		go scanUDPPort(wg, jobs, workerResultsChan)
	}

	totalNumOfHosts := util.HostsInIP4Network(targets)
	spinner, err := pterm.DefaultSpinner.Start("Scanning ", totalNumOfHosts, " hosts")
	if err != nil {
		return UDPScanResults{}, err
	}
	defer spinner.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	senderDone := make(chan struct{})

	go sendPortScanningJobs(ctx, senderDone, jobs, opts.Targets, opts.TargetPorts, opts.timeout)
	scanner.stats.TotalNumOfHosts = totalNumOfHosts

	scanResultsChan := make(chan UDPScanResults)
	go getUDPScanResults(ctx, scanner, workerResultsChan, scanResultsChan)

	<-senderDone             // wait for sender to send all jobs
	wg.Wait()                // wait for all to workers to finish
	close(workerResultsChan) // tell the main Woker to stop and send results

	scanResults := <-scanResultsChan
	return scanResults, nil
}

func scanUDPPort(wg *sync.WaitGroup, jobs chan PortScanJob, resultsChan chan<- PortScanWorkerResult) {
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
				Number:   uint(target.Port()),
				Protocol: proto,
			},
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

		err = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		if err != nil {
			result.Port.State = PortStateClosed
			resultsChan <- result
			continue
		}
		buf := make([]byte, 1)
		conn.Write(buf) // first write to the connection so we can get responses if any
		_, err = conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// if we got a timeout, it can be because the port is filtered or open but silent
				// BUG: This logic only works for hosts that are up. If a host is down, it will also timeout.
				// Possible Fix is to first do a ping scan before actually doing port Scanning

				result.Port.State = PortStateOpen
				result.Port.Name = util.Service(layers.UDPPort(target.Port()).String())
			} else {
				// any other error means the port is closed
				result.Port.State = PortStateClosed
			}
		} else {
			result.Port.State = PortStateOpen
			result.Port.Name = util.Service(layers.UDPPort(target.Port()).String())
		}

		resultsChan <- result
	}
}

func getUDPScanResults(ctx context.Context, scanner *UDPScanner, workerResultsChan chan PortScanWorkerResult, scanResultsChan chan UDPScanResults) {
	// To Be Run By Main Worker
	scanResults := UDPScanResults{
		ResultMap: make(map[netip.Addr]HostResult),
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
			hostIP := result.HostIP
			hostResults := scanResults.ResultMap[hostIP]
			if hostResults.Ports == nil {
				hostResults.Ports = make(map[uint]Port) // make new map if not created yet
			}
			hostResults.Ports[result.Port.Number] = result.Port
			hostResults.HostName = scanner.hostNames[hostIP] // put the hostname of the address in the HostResult struct
			switch result.Port.State {
			case PortStateOpen:
				hostResults.OpenPorts++
			case PortStateClosed:
				hostResults.ClosedPorts++
			}
			scanResults.ResultMap[hostIP] = hostResults
		}
	}
}
