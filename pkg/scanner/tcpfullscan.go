package scanner

import (
	"context"
	"fmt"
	"io"
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

type TCPFullScanOptions struct {
	Targets             []netip.Prefix
	TargetPorts         []uint
	Workers             uint
	ResponseTimeout     time.Duration
	HostNames           map[netip.Addr]string
	AddUnknownHostNames bool
	MessageNotifier     notifier.Notifier
	logger              io.Writer
}

type TCPFullScanResults struct {
	ResultMap map[netip.Addr]HostResult
}

func (TCPFullScanResults) ResultType() ScanResultType {
	return TCPFullScanScanResultType
}

func (r TCPFullScanResults) String() string {
	stringBuilder := strings.Builder{}
	fmt.Fprintf(&stringBuilder, "TCP Full Scan Results.\n\n")
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

type TCPFullScanStats struct {
	TotalNumOfHosts int
}

type TCPFullScanner struct {
	TCPFullScanOptions
	results TCPFullScanResults
	stats   TCPFullScanStats
}

func NewTCPFullScanner(opts TCPFullScanOptions) *TCPFullScanner {
	if opts.HostNames == nil {
		opts.HostNames = make(map[netip.Addr]string)
	}
	return &TCPFullScanner{
		TCPFullScanOptions: opts,
		results: TCPFullScanResults{
			ResultMap: make(map[netip.Addr]HostResult),
		},
		stats: TCPFullScanStats{},
	}
}

func (s *TCPFullScanner) SendResultsViaNotifier() error {
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

func (s *TCPFullScanner) Scan() error {
	results, err := runTCPFullScan(s)
	if err != nil {
		return err
	}
	s.results = results
	return nil
}

func (s *TCPFullScanner) Results() ScanResults {
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

func (s *TCPFullScanner) Stats() ScanStats {
	return s.stats
}

func runTCPFullScan(scanner *TCPFullScanner) (TCPFullScanResults, error) {
	opts := scanner.TCPFullScanOptions
	targets := opts.Targets
	ports := opts.TargetPorts

	numWorkers := opts.Workers

	if len(targets) == 0 {
		return TCPFullScanResults{}, fmt.Errorf("no hosts to scan provided")
	}
	if len(ports) == 0 {
		return TCPFullScanResults{}, fmt.Errorf("no ports provided for scanning")
	}

	jobs := make(chan PortScanJob, numWorkers)
	workerResultsChan := make(chan PortScanWorkerResult, numWorkers)
	wg := &sync.WaitGroup{}
	for range numWorkers {
		wg.Add(1)
		go scanTCPPort(wg, jobs, workerResultsChan)
	}

	totalNumOfHosts := util.HostsInIP4Network(targets)
	scanner.stats.TotalNumOfHosts = totalNumOfHosts
	spinner, err := pterm.DefaultSpinner.Start("Scanning ", totalNumOfHosts, " hosts")
	if err != nil {
		return TCPFullScanResults{}, err
	}
	defer spinner.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	senderDone := make(chan struct{})

	go sendPortScanningJobs(ctx, senderDone, jobs, opts.Targets, opts.TargetPorts, opts.ResponseTimeout)

	scanResultsChan := make(chan TCPFullScanResults)
	go getTCPFullScanResults(ctx, scanner, workerResultsChan, scanResultsChan)

	<-senderDone             // wait for sender to send all jobs
	wg.Wait()                // wait for all to workers to finish
	close(workerResultsChan) // tell main worker to stop

	scanResults := <-scanResultsChan
	return scanResults, nil
}

func getTCPFullScanResults(ctx context.Context, scanner *TCPFullScanner, workerResultsChan chan PortScanWorkerResult, scanResultsChan chan TCPFullScanResults) {
	// To Be Run By Main Worker
	scanResults := TCPFullScanResults{
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
			hostResults.HostName = scanner.HostNames[hostIP] // put the hostname of the address in the HostResult struct
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
