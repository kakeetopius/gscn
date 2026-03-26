package scanner

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/kakeetopius/gscn/internal/util"
)

type TCPFullScanOptions struct {
	Targets     []netip.Prefix
	TargetPorts []uint
	workers     uint
	timeout     time.Duration
	logger      io.Writer
}

type TCPFullScanResults struct {
	ResultMap map[netip.Addr]HostResult
}

func (TCPFullScanResults) ResultType() ScanResultType {
	return TCPFullScanScanResultType
}

type TCPFullScanStats struct {
	TotalNumOfHosts int
}

type TCPFullScanner struct {
	opts                    *TCPFullScanOptions
	results                 TCPFullScanResults
	stats                   TCPFullScanStats
	resolveUnknownHostNames bool
	hostNames               map[netip.Addr]string
}

func NewTCPFullScanner(opts *TCPFullScanOptions) Scanner {
	resultMap := make(map[netip.Addr]HostResult)
	return &TCPFullScanner{
		opts: opts,
		results: TCPFullScanResults{
			ResultMap: resultMap,
		},
		stats:                   TCPFullScanStats{},
		hostNames:               make(map[netip.Addr]string),
		resolveUnknownHostNames: false,
	}
}

func (s *TCPFullScanner) WithHostNames(h map[netip.Addr]string, addUnknown bool) Scanner {
	if h != nil {
		maps.Copy(s.hostNames, h)
	}
	if addUnknown {
		s.resolveUnknownHostNames = true
	}
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

func (s *TCPFullScanner) WithNotifier(notifier.Notifier) Scanner {
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
	workerResultsChan := make(chan PortScanWorkerResult, numWorkers)
	wg := &sync.WaitGroup{}
	for range numWorkers {
		wg.Add(1)
		go scanTCPPort(wg, jobs, workerResultsChan)
	}

	totalNumOfHosts := util.HostsInIP4Network(targets)
	scanner.stats.TotalNumOfHosts = totalNumOfHosts
	sendPortScanningJobs(jobs, opts.Targets, opts.TargetPorts)

	ctx, cancel := context.WithTimeout(context.Background(), scanner.opts.timeout)
	defer cancel()
	scanResultsChan := make(chan TCPFullScanResults)
	go getTCPFullScanResults(ctx, scanner, workerResultsChan, scanResultsChan)

	close(jobs) // stops the for loop in workers
	wg.Wait()   // wait for all to workers to finish
	cancel()    // tell the main Woker to stop and send results

	scanResults := <-scanResultsChan
	return scanResults, nil
}

func getTCPFullScanResults(ctx context.Context, scanner *TCPFullScanner, workerResultsChan chan PortScanWorkerResult, scanResultsChan chan TCPFullScanResults) {
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

func scanTCPPort(wg *sync.WaitGroup, jobs chan netip.AddrPort, resultsChan chan<- PortScanWorkerResult) {
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
			result.Port.Name = util.ServiceFromGoPacketString(layers.TCPPort(target.Port()).String())
		}

		resultsChan <- result
	}
	wg.Done()
}
