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

type UDPScanStats struct {
	TotalNumOfHosts int
}

type UDPScanner struct {
	opts                    *UDPScanOptions
	results                 UDPScanResults
	stats                   UDPScanStats
	resolveUnknownHostNames bool
	hostNames               map[netip.Addr]string
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

func (s *UDPScanner) WithNotifier(notifier.Notifier) Scanner {
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

	jobs := make(chan netip.AddrPort, numWorkers)
	workerResultsChan := make(chan PortScanWorkerResult, numWorkers)
	wg := &sync.WaitGroup{}
	for range numWorkers {
		wg.Add(1)
		go scanUDPPort(wg, jobs, workerResultsChan)
	}

	totalNumOfHosts := util.HostsInIP4Network(targets)
	scanner.stats.TotalNumOfHosts = totalNumOfHosts
	sendPortScanningJobs(jobs, opts.Targets, opts.TargetPorts)

	ctx, cancel := context.WithCancel(context.Background())
	scanResultsChan := make(chan UDPScanResults)
	go getUDPScanResults(ctx, scanner, workerResultsChan, scanResultsChan)

	close(jobs) // stops the for loop in workers
	wg.Wait()   // wait for all to workers to finish
	cancel()    // tell the main Woker to stop and send results

	scanResults := <-scanResultsChan
	return scanResults, nil
}

func scanUDPPort(wg *sync.WaitGroup, jobs chan netip.AddrPort, resultsChan chan<- PortScanWorkerResult) {
	for target := range jobs {
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
			Timeout: 1 * time.Second,
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
				result.Port.State = PortStatePossibleFilter
				result.Port.Name = util.ServiceFromGoPacketString(layers.UDPPort(target.Port()).String())
			} else {
				// any other error means the port is closed
				result.Port.State = PortStateClosed
			}
		} else {
			result.Port.State = PortStateOpen
			result.Port.Name = util.ServiceFromGoPacketString(layers.UDPPort(target.Port()).String())
		}

		resultsChan <- result
	}
	wg.Done()
}

func getUDPScanResults(ctx context.Context, scanner *UDPScanner, workerResultsChan chan PortScanWorkerResult, scanResultsChan chan UDPScanResults) {
	// To Be Run By Main Worker
	scanResults := UDPScanResults{
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
