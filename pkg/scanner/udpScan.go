package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/pterm/pterm"
)

type UDPScanOptions struct {
	TargetHosts []netip.Prefix
	TargetPorts []uint
	workers     uint
	generalScanOptions
}

type UDPScanResults struct {
	ResultMap map[netip.Addr]HostResult
}

func (UDPScanResults) ResultType() ScanResultType {
	return UDPScanResultType
}

type UDPScanStats struct{}

type UDPScanner struct {
	opts      *UDPScanOptions
	results   UDPScanResults
	stats     UDPScanStats
	hostNames map[netip.Addr]string
}

func NewUDPScanner(opts *UDPScanOptions) *UDPScanner {
	resultMap := make(map[netip.Addr]HostResult)
	return &UDPScanner{
		opts: opts,
		results: UDPScanResults{
			ResultMap: resultMap,
		},
		stats:     UDPScanStats{},
		hostNames: make(map[netip.Addr]string),
	}
}

func (s *UDPScanner) WithWorkers(numOfWorkers uint) *UDPScanner {
	s.opts.workers = numOfWorkers
	return s
}

func (s *UDPScanner) WithTimeout(timeout time.Duration) *UDPScanner {
	s.opts.Timeout = timeout
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
	addScanStatsToUDPResults(s.results)
	return s.results
}

func (s *UDPScanner) Stats() ScanStats {
	return s.stats
}

func runUDPScan(scanner *UDPScanner) (UDPScanResults, error) {
	opts := scanner.opts
	targets := opts.TargetHosts
	ports := opts.TargetPorts

	numWorkers := opts.workers

	if len(targets) == 0 {
		return UDPScanResults{}, fmt.Errorf("no hosts to scan provided")
	}
	if len(ports) == 0 {
		return UDPScanResults{}, fmt.Errorf("no ports provided for scanning")
	}

	jobs := make(chan netip.AddrPort, numWorkers)
	workerResultsChan := make(chan WorkerResult, numWorkers)
	wg := &sync.WaitGroup{}
	for range numWorkers {
		wg.Add(1)
		go scanUDPPort(wg, jobs, workerResultsChan)
	}

	totalNumOfHosts := util.HostsInIP4Network(targets)
	spinner, err := pterm.DefaultSpinner.Start(fmt.Sprintf("Scanning %v Host(s)", totalNumOfHosts))
	if err != nil {
		return UDPScanResults{}, err
	}
	sendUDPJobs(jobs, opts)

	ctx, cancel := context.WithCancel(context.Background())
	scanResultsChan := make(chan UDPScanResults)
	go getUDPScanResults(ctx, workerResultsChan, scanResultsChan)

	close(jobs) // stops the for loop in workers
	wg.Wait()   // wait for all to workers to finish
	cancel()    // tell the main Woker to stop and send results

	spinner.Success("Done")
	scanResults := <-scanResultsChan
	return scanResults, nil
}

func scanUDPPort(wg *sync.WaitGroup, jobs chan netip.AddrPort, resultsChan chan<- WorkerResult) {
	for target := range jobs {
		proto := ""
		if target.Addr().Is4() {
			proto = "udp"
		} else {
			proto = "udp6"
		}
		result := WorkerResult{
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

func sendUDPJobs(jobChan chan netip.AddrPort, opts *UDPScanOptions) {
	for _, target := range opts.TargetHosts {
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

func getUDPScanResults(ctx context.Context, workerResultsChan chan WorkerResult, scanResultsChan chan UDPScanResults) {
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
			scanResults.ResultMap[hostIP] = hostResults
		}
	}
}

func addScanStatsToUDPResults(results UDPScanResults) {
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
