// Package scan is used to get various network information about hosts on a network.
package scan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/util"
	"github.com/pterm/pterm"
	"github.com/urfave/cli/v3"
)

type PortState uint8

const (
	PortStateOpen PortState = iota
	PortStateClosed
	PortStatePossibleFilter
)

type Port struct {
	Number   uint
	Name     string
	Protocol string
	State    PortState
}

type ScanTarget struct {
	netip.Prefix
}

type ScanOptions struct {
	TargetHosts []ScanTarget
	TargetPorts []uint
	Timeout     int
	Scanner     func(opts *ScanOptions, wg *sync.WaitGroup, jobs chan netip.AddrPort, resultsChan chan<- WorkerResult)
}

// HostResult is the result of a single host after scanning
type HostResult struct {
	Ports       map[uint]Port
	OpenPorts   int
	ClosedPorts int
}

// WorkerResult is the tesult returned by Scanning workers
type WorkerResult struct {
	HostIP netip.Addr
	Port   Port
}

// ScanResults is results of all the scanned hosts
type ScanResults map[netip.Addr]HostResult

var HostNames = make(map[netip.Addr]string)

func RunScan(clictx context.Context, cmd *cli.Command) error {
	var opts ScanOptions
	var err error
	targets := make([]ScanTarget, 0)
	ports := make([]uint, 0)

	numWorkers := cmd.Int("workers")
	if numWorkers > 500 {
		return fmt.Errorf("number of workers cannot go above 500")
	}

	if targetStr := cmd.String("target"); targetStr != "" {
		targets, err = scanTargetsFromString(targetStr)
		if err != nil {
			return err
		}
	}
	if len(targets) == 0 {
		fmt.Println()
		pterm.Info.Println("No targets provided")
		return nil
	}
	opts.TargetHosts = targets
	if portStr := cmd.String("ports"); portStr != "" {
		ports, err = util.PortsFromString(portStr)
		if err != nil {
			return err
		}
	}
	if len(ports) == 0 {
		fmt.Println()
		pterm.Info.Println("No ports provided")
		return nil
	}
	opts.TargetPorts = ports

	if cmd.Bool("udp") {
		opts.Scanner = ScanHostUDPPort
	} else {
		opts.Scanner = ScanHostTCPPort
	}

	jobs := make(chan netip.AddrPort, numWorkers)
	workerResultsChan := make(chan WorkerResult, numWorkers)
	wg := &sync.WaitGroup{}
	for range numWorkers {
		wg.Add(1)
		go opts.Scanner(&opts, wg, jobs, workerResultsChan)
	}

	totalNumOfHosts := totalNumOfScanTargets(targets)
	spinner, err := pterm.DefaultSpinner.Start(fmt.Sprintf("Scanning %v Host(s)", totalNumOfHosts))
	if err != nil {
		return err
	}
	sendJobs(jobs, opts)

	ctx, cancel := context.WithCancel(context.Background())
	scanResultsChan := make(chan ScanResults)
	go getScanResults(ctx, workerResultsChan, scanResultsChan)

	close(jobs) // stops the for loop in workers
	wg.Wait()   // wait for all to workers to finish
	cancel()    // tell the main Woker to stop and send results

	spinner.Success("Done")
	scanResults := <-scanResultsChan
	addScanStatsToResults(scanResults)
	PrintScanResults(scanResults)
	return nil
}

func ScanHostTCPPort(opts *ScanOptions, wg *sync.WaitGroup, jobs chan netip.AddrPort, resultsChan chan<- WorkerResult) {
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
			result.Port.Name = serviceFromGoPacketString(layers.TCPPort(target.Port()).String())
		}

		resultsChan <- result
	}
	wg.Done()
}

func ScanHostUDPPort(opts *ScanOptions, wg *sync.WaitGroup, jobs chan netip.AddrPort, resultsChan chan<- WorkerResult) {
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
				result.Port.Name = serviceFromGoPacketString(layers.UDPPort(target.Port()).String())
			} else {
				// any other error means the port is closed
				result.Port.State = PortStateClosed
			}
		} else {
			result.Port.State = PortStateOpen
			result.Port.Name = serviceFromGoPacketString(layers.UDPPort(target.Port()).String())
		}

		resultsChan <- result
	}
	wg.Done()
}

func PrintScanResults(results ScanResults) {
	var tableData [][]string
	for host, hostResults := range results {
		tableData = pterm.TableData{{"Port", "State", "Service"}}
		name := ""
		if hostname, ok := HostNames[host]; ok {
			name = fmt.Sprintf("(%v)", hostname)
		}
		fmt.Printf("\nScan Report for %v %v\n", host, name)
		for _, port := range hostResults.Ports {
			if port.State == PortStateClosed {
				continue // no need to add closed port to table
			}
			tcpService := serviceFromGoPacketString(layers.TCPPort(port.Number).String())
			tableData = append(tableData, []string{fmt.Sprintf("%v/%v", port.Protocol, port.Number), port.State.String(), tcpService})
		}
		if hostResults.OpenPorts > 0 {
			pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(tableData).Render()
		}
		fmt.Println("Ports Scanned: ", hostResults.OpenPorts+hostResults.ClosedPorts)
		fmt.Println("Open Ports: ", hostResults.OpenPorts)
		fmt.Println("Closed Ports: ", hostResults.ClosedPorts)
	}
}

func sendJobs(jobChan chan netip.AddrPort, opts ScanOptions) {
	for _, target := range opts.TargetHosts {
		for _, port := range opts.TargetPorts {
			if util.OnlyIPInRange(target.Prefix) {
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

func getScanResults(ctx context.Context, workerResultsChan chan WorkerResult, scanResultsChan chan ScanResults) {
	// To Be Run By Main Worker
	scanResults := make(ScanResults)
	for {
		select {
		case <-ctx.Done():
			scanResultsChan <- scanResults
			return
		case result := <-workerResultsChan:
			hostIP := result.HostIP
			hostResults := scanResults[hostIP]
			if hostResults.Ports == nil {
				hostResults.Ports = make(map[uint]Port) // make new map if not created yet
			}
			hostResults.Ports[result.Port.Number] = result.Port
			scanResults[hostIP] = hostResults
		}
	}
}

func serviceFromGoPacketString(s string) string {
	// format: number(name) eg 80(http)
	if s == "" {
		return s
	}
	firstBracket := strings.Index(s, "(")
	secondBracket := strings.Index(s, ")")
	if firstBracket == -1 || secondBracket == -1 {
		// if gopacket just returned number alone without service
		return ""
	}
	return s[firstBracket+1 : secondBracket]
}

func addScanStatsToResults(results ScanResults) {
	for host, hostResult := range results {
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
		results[host] = stats
	}
}

func scanTargetsFromString(s string) ([]ScanTarget, error) {
	// Example: 10.1.1.1/24,10.1.1.1,bing.com,10.1.1.1-2,google.com
	commaSeparatedTargets := strings.Split(s, ",")
	targets := make([]ScanTarget, 0, 5)

	// For dns lookup incase ip address parsing fails.
	resolver := net.Resolver{}

	for _, targetString := range commaSeparatedTargets {
		var err error
		if strings.ContainsRune(targetString, '/') {
			// CIDR Notation Provided eg 10.1.1.1/24
			var network netip.Prefix
			network, err = netip.ParsePrefix(targetString)
			if err == nil {
				targets = append(targets, ScanTarget{Prefix: network})
			}
		} else if strings.ContainsRune(targetString, '-') {
			// IP Range provided eg 10.1.1.1-10
			var IPsInRange []netip.Prefix
			IPsInRange, err = util.ParseIPRange(targetString)
			if err == nil {
				for _, ip := range IPsInRange {
					targets = append(targets, ScanTarget{Prefix: ip})
				}
			}
		} else {
			// Single IP Presumed eg 10.1.1.1
			var addr netip.Addr
			addr, err = netip.ParseAddr(targetString)
			bitlen := 32
			if addr.Is6() {
				bitlen = 128
			}
			if err == nil {
				targets = append(targets, ScanTarget{Prefix: netip.PrefixFrom(addr, bitlen)})
			}
		}
		if err != nil {
			// if some errors occured while Parsing assume it is domain name
			IPs, resolverr := resolver.LookupIP(context.Background(), "ip4", strings.Trim(targetString, " "))
			if resolverr != nil {
				return nil, resolverr
			}
			addr, ok := netip.AddrFromSlice(IPs[0])
			if !ok {
				return nil, fmt.Errorf("could not resolve: %v", targetString)
			}
			HostNames[addr] = targetString
			targets = append(targets, ScanTarget{Prefix: netip.PrefixFrom(addr, 32)})
		}
	}

	return util.Unique(targets), nil
}

func totalNumOfScanTargets(targets []ScanTarget) int {
	total := 0
	for _, targetNet := range targets {
		total += util.HostsInIP4Network([]netip.Prefix{targetNet.Prefix})
	}
	return total
}

func (p PortState) String() string {
	var s string
	switch p {
	case PortStateOpen:
		s = "open"
	case PortStateClosed:
		s = "closed"
	case PortStatePossibleFilter:
		s = "open | filtered"
	}

	return s
}
