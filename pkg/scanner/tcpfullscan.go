package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/pterm/pterm"
)

type TCPFullScanOptions struct {
	Targets     []netip.Prefix
	TargetPorts []uint
	workers     uint
	timeout     time.Duration
	logger      io.Writer
}

// HostResult is the result of a single host after scanning
type HostResult struct {
	Ports       map[uint]Port
	HostName    string
	OpenPorts   int
	ClosedPorts int
}

// WorkerResult is the tesult returned by Scanning workers
type WorkerResult struct {
	HostIP netip.Addr
	Port   Port
}

type TCPFullScanResults struct {
	ResultMap map[netip.Addr]HostResult
}

func (TCPFullScanResults) ResultType() ScanResultType {
	return TCPFullScanScanResultType
}

type TCPFullScanStats struct{}

type TCPFullScanner struct {
	opts      *TCPFullScanOptions
	results   TCPFullScanResults
	stats     TCPFullScanStats
	hostNames map[netip.Addr]string
}

func NewTCPFullScanner(opts *TCPFullScanOptions) Scanner {
	resultMap := make(map[netip.Addr]HostResult)
	return &TCPFullScanner{
		opts: opts,
		results: TCPFullScanResults{
			ResultMap: resultMap,
		},
		stats:     TCPFullScanStats{},
		hostNames: make(map[netip.Addr]string),
	}
}

func (s *TCPFullScanner) WithHostNames() Scanner {
	return s
}

func (s *TCPFullScanner) WithVendorInfo() Scanner {
	return s
}

func (s *TCPFullScanner) WithWorkers(numOfWorkers int) Scanner {
	s.opts.workers = uint(numOfWorkers)
	return s
}

func (s *TCPFullScanner) WithTimeout(timeout time.Duration) Scanner {
	s.opts.timeout = timeout
	return s
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
	addScanStatsToResults(s.results)
	return s.results
}

func (s *TCPFullScanner) Stats() ScanStats {
	return s.stats
}

func runTCPFullScan(scanner *TCPFullScanner) (TCPFullScanResults, error) {
	opts := scanner.opts
	targets := opts.Targets
	ports := opts.TargetPorts

	numWorkers := opts.workers

	if len(targets) == 0 {
		return TCPFullScanResults{}, fmt.Errorf("no hosts to scan provided")
	}
	if len(ports) == 0 {
		return TCPFullScanResults{}, fmt.Errorf("no ports provided for scanning")
	}

	jobs := make(chan netip.AddrPort, numWorkers)
	workerResultsChan := make(chan WorkerResult, numWorkers)
	wg := &sync.WaitGroup{}
	for range numWorkers {
		wg.Add(1)
		go scanTCPPort(wg, jobs, workerResultsChan)
	}

	totalNumOfHosts := util.HostsInIP4Network(targets)
	spinner, err := pterm.DefaultSpinner.Start(fmt.Sprintf("Scanning %v Host(s)", totalNumOfHosts))
	if err != nil {
		return TCPFullScanResults{}, err
	}
	sendJobs(jobs, opts)

	ctx, cancel := context.WithCancel(context.Background())
	scanResultsChan := make(chan TCPFullScanResults)
	go getScanResults(ctx, workerResultsChan, scanResultsChan)

	close(jobs) // stops the for loop in workers
	wg.Wait()   // wait for all to workers to finish
	cancel()    // tell the main Woker to stop and send results

	spinner.Success("Done")
	scanResults := <-scanResultsChan
	return scanResults, nil
}

func scanTCPPort(wg *sync.WaitGroup, jobs chan netip.AddrPort, resultsChan chan<- WorkerResult) {
	for target := range jobs {
		proto := ""
		if target.Addr().Is4() {
			proto = "tcp"
		} else {
			proto = "tcp6"
		}
		dialer := net.Dialer{
			Timeout: 1 * time.Second,
		}
		_, err := dialer.Dial(proto, target.String())

		result := WorkerResult{
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
			result.Port.Name = util.ServiceFromGoPacketString(layers.TCPPort(target.Port()).String())
		}

		resultsChan <- result
	}
	wg.Done()
}

func sendJobs(jobChan chan netip.AddrPort, opts *TCPFullScanOptions) {
	for _, target := range opts.Targets {
		for _, port := range opts.TargetPorts {
			if util.OnlyIPInRange(target) {
				addrPort := netip.AddrPortFrom(target.Addr(), uint16(port))
				jobChan <- addrPort
				continue
			}
			netAddr := target.Masked()
			addr := netAddr.Addr().Next()
			for netAddr.Contains(addr) {
				// loop over range of IPs
				addrPort := netip.AddrPortFrom(addr, uint16(port))
				jobChan <- addrPort
				addr = addr.Next()
			}
		}
	}
}

func getScanResults(ctx context.Context, workerResultsChan chan WorkerResult, scanResultsChan chan TCPFullScanResults) {
	// To Be Run By Main Worker
	scanResults := TCPFullScanResults{
		ResultMap: make(map[netip.Addr]HostResult),
	}
	for {
		select {
		case <-ctx.Done():
			scanResultsChan <- scanResults
			return
		case result := <-workerResultsChan:
			hostIP := result.HostIP
			hostResults := scanResults.ResultMap[hostIP]
			if hostResults.Ports == nil {
				hostResults.Ports = make(map[uint]Port) // make new map if not created yet
			}
			hostResults.Ports[result.Port.Number] = result.Port
			scanResults.ResultMap[hostIP] = hostResults
		}
	}
}

func addScanStatsToResults(results TCPFullScanResults) {
	for host, hostResult := range results.ResultMap {
		closed := 0
		open := 0
		for _, port := range hostResult.Ports {
			switch port.State {
			case PortStateOpen:
				open++
			case PortStateClosed:
				closed++
			case PortStatePossibleFilter:
				open++
			}
		}
		stats := HostResult{
			Ports:       hostResult.Ports,
			ClosedPorts: closed,
			OpenPorts:   open,
		}
		results.ResultMap[host] = stats
	}
}
