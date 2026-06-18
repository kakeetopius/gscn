package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/log"
	"github.com/kakeetopius/gscn/internal/notifier"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/pterm/pterm"
)

type UDPScanner struct {
	UDPScanOptions
	results    UDPScanResults
	stats      UDPScanStats
	hostStates map[netip.Addr]PingResult
	logger     log.Logger
}

type UDPScanOptions struct {
	Targets             []netip.Prefix
	TargetPorts         []uint
	Workers             int
	PingTimeout         time.Duration
	PingCount           int
	ResponseTimeout     time.Duration
	HostNames           map[netip.Addr]string
	AddUnknownHostNames bool
	MessageNotifier     notifier.Notifier

	PrintUpOnly   bool
	PrintOpenOnly bool
}

type UDPScanResults struct {
	ResultMap map[netip.Addr]HostResult
}

type UDPScanStats struct {
	TotalNumOfHosts int
	ScanTime        time.Duration
}

func NewUDPScanner(opts UDPScanOptions) *UDPScanner {
	if opts.HostNames == nil {
		opts.HostNames = make(map[netip.Addr]string)
	}
	return &UDPScanner{
		UDPScanOptions: opts,
		results: UDPScanResults{
			ResultMap: make(map[netip.Addr]HostResult),
		},
		stats:  UDPScanStats{},
		logger: log.NewLogger(true),
	}
}

func (s *UDPScanner) Scan() error {
	startTime := time.Now()
	results, err := runUDPScan(s)
	if err != nil {
		return err
	}
	stopTime := time.Now()
	s.stats.ScanTime = stopTime.Sub(startTime)
	s.results = results

	s.addResultsInfo()
	return nil
}

func (s *UDPScanner) SendResultsViaNotifier() error {
	if s.MessageNotifier == nil {
		return fmt.Errorf("udpscanner: no notifier is set")
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
		spinner.Fail()
		return err
	}

	return nil
}

func (s *UDPScanner) PrintResults() {
	printScanResultsMap(s.results.ResultMap, s.stats.ScanTime, s.PrintUpOnly, s.PrintOpenOnly)
}

func (s *UDPScanner) Results() UDPScanResults {
	return s.results
}

func (s *UDPScanner) Stats() UDPScanStats {
	return s.stats
}

func (s *UDPScanner) addResultsInfo() {
	if s.AddUnknownHostNames {
		spinner, _ := pterm.DefaultSpinner.Start("Resolving Host Names....")
		defer spinner.Success("Resolving Done")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for host, results := range s.results.ResultMap {
			if results.HostName != "" {
				continue
			}
			name := util.ReverseLookup(ctx, host.String())
			results.HostName = name
			s.results.ResultMap[host] = results
		}
	}

	for _, hostResult := range s.results.ResultMap {
		slices.SortFunc(hostResult.Ports, func(a, b Port) int {
			return int(a.Number - b.Number)
		})
	}
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

func runUDPScan(scanner *UDPScanner) (UDPScanResults, error) {
	opts := scanner.UDPScanOptions
	targets := opts.Targets
	ports := opts.TargetPorts

	numWorkers := opts.Workers

	pterm.Warning.Println("UDP Scans are not reliable and may show inconsistent or wrong results.")
	if len(targets) == 0 {
		return UDPScanResults{}, fmt.Errorf("no hosts to scan provided")
	}
	if len(ports) == 0 {
		return UDPScanResults{}, fmt.Errorf("no ports provided for scanning")
	}

	pingResults, err := pingHosts(targets, opts.PingTimeout, int(opts.Workers), opts.PingCount) // first check if hosts are up.
	if err != nil {
		return UDPScanResults{}, err
	}
	scanner.hostStates = pingResults.ResultMap

	jobs := make(chan PortScanJob, numWorkers)
	workerResultsChan := make(chan PortScanWorkerResult, numWorkers)
	wg := &sync.WaitGroup{}
	for range numWorkers {
		wg.Add(1)
		go scanUDPPort(scanner, wg, jobs, workerResultsChan)
	}

	spinner, err := pterm.DefaultSpinner.Start("Scanning hosts")
	if err != nil {
		return UDPScanResults{}, err
	}
	defer spinner.Success("Scanning Done")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	senderDone := make(chan struct{})

	go sendPortScanningJobs(ctx, senderDone, jobs, opts.Targets, opts.TargetPorts, opts.ResponseTimeout)

	scanResultsChan := make(chan UDPScanResults)
	go getUDPScanResults(ctx, scanner, workerResultsChan, scanResultsChan)

	<-senderDone             // wait for sender to send all jobs
	wg.Wait()                // wait for all the workers to finish
	close(workerResultsChan) // tell the main Woker to stop and send results

	scanResults := <-scanResultsChan
	return scanResults, nil
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
				Number:   uint(target.Port()),
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
			hostResults, found := scanResults.ResultMap[hostIP]
			if !found {
				hostResults.Ports = make([]Port, 0, numberOfPortsToScan)
				hostResults.HostName = scanner.HostNames[hostIP]             // get hostname from scanner options
				hostResults.HostState = scanner.hostStates[hostIP].HostState // get hostState from scanner options
				hostResults.AverageRTT = scanner.hostStates[hostIP].AverageRTT
			}
			hostResults.Ports = append(hostResults.Ports, result.Port)

			switch result.Port.State {
			case PortStateOpen:
				hostResults.OpenPorts++
			case PortStateClosed:
				hostResults.ClosedPorts++
			case PortStatePossibleFilter:
				hostResults.FilteredPorts++
			}
			scanResults.ResultMap[hostIP] = hostResults
		}
	}
}

func pingHosts(targets []netip.Prefix, pingTimeout time.Duration, workers int, pingCount int) (PingScanResults, error) {
	pinger := NewPingScanner(PingScanOptions{
		Targets:     targets,
		PingTimeout: pingTimeout,
		Workers:     workers,
		PingCount:   pingCount,
	})

	err := pinger.Scan()
	if err != nil {
		return PingScanResults{}, err
	}
	results := pinger.Results()

	return results, nil
}
