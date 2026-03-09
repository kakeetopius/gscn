// Package scan is used to get various network information about hosts on a network.
package scan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/netutils"
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
		ports, err = portsFromString(portStr)
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

	spinner, err := pterm.DefaultSpinner.Start("Scanning Host(s)")
	if err != nil {
		return err
	}
	sendJobs(jobs, opts)

	ctx, cancel := context.WithCancel(context.Background())
	scanResultsChan := make(chan ScanResults)
	go getScanResults(ctx, workerResultsChan, scanResultsChan)

	close(jobs) // stops the for loop in workers
	wg.Wait()   // wait for all to workers to exit
	cancel()    // tell the main Woker to stop and send results

	spinner.Success("Done")
	scanResults := <-scanResultsChan
	addScanStatsToResults(scanResults)
	PrintScanResults(scanResults)
	return nil
}

func ScanHostTCPPort(opts *ScanOptions, wg *sync.WaitGroup, jobs chan netip.AddrPort, resultsChan chan<- WorkerResult) {
	for target := range jobs {
		tcpAddr := net.TCPAddr{
			IP:   target.Addr().AsSlice(),
			Port: int(target.Port()),
		}
		proto := ""
		if target.Addr().Is4() {
			proto = "tcp"
		} else {
			proto = "tcp6"
		}
		_, err := net.DialTCP(proto, nil, &tcpAddr)

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
		udpAddr := net.UDPAddr{
			IP:   target.Addr().AsSlice(),
			Port: int(target.Port()),
		}
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

		conn, err := net.DialUDP(proto, nil, &udpAddr)
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
		conn.Write(buf) // first write to the connection so we can het responses if any
		_, err = conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// if we got a timeout, it can be because the port is filtered or open but silent
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
			var state string
			switch port.State {
			case PortStateOpen:
				state = "open"
			case PortStatePossibleFilter:
				state = "open|filtered"
			case PortStateClosed:
				state = "closed"
				continue // no need to add closed ports to the table to print
			}
			tcpService := serviceFromGoPacketString(layers.TCPPort(port.Number).String())
			tableData = append(tableData, []string{fmt.Sprintf("%v/%v", port.Protocol, port.Number), state, tcpService})
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
			if onlyIPInRange(target.Prefix) {
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

func onlyIPInRange(addr netip.Prefix) bool {
	if addr.Bits() == 32 && addr.Addr().Is4() {
		return true
	} else if addr.Bits() == 128 && addr.Addr().Is6() {
		return true
	}
	return false
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
			IPsInRange, err = TryParseIPRange(targetString)
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
			resolver := net.Resolver{}
			IPs, resolverr := resolver.LookupIP(context.Background(), "ip4", targetString)
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

	return netutils.Unique(targets), nil
}

func TryParseIPRange(s string) ([]netip.Prefix, error) {
	if s == "" {
		return nil, fmt.Errorf("error parsing target %v -> Invalid range", s)
	}

	IPPrefixes := make([]netip.Prefix, 0)
	dashIndex := strings.LastIndex(s, "-")
	if dashIndex >= len(s) {
		return nil, fmt.Errorf("error parsing target -> %v", s)
	}
	lastDotIndex := strings.LastIndex(s, ".")
	if lastDotIndex == -1 {
		return nil, fmt.Errorf("error parsing -> %v", s)
	}
	baseIP := s[:lastDotIndex+1]
	lower, err := strconv.Atoi(s[lastDotIndex+1 : dashIndex])
	if err != nil {
		return nil, fmt.Errorf("error parsing target %v -> %v", s, err)
	}
	upper, err := strconv.Atoi(s[dashIndex+1:])
	if err != nil {
		return nil, fmt.Errorf("error parsing target %v -> %v", s, err)
	}
	if lower > upper {
		return nil, fmt.Errorf("error parsing target %v -> invalid range", s)
	} else if upper >= 256 {
		return nil, fmt.Errorf("error parsing target %v -> range cannot go above 255", s)
	} else if lower < 0 {
		return nil, fmt.Errorf("error parsing target %v -> range cannot be below zero", s)
	}

	for i := lower; i <= upper; i++ {
		targetStr := fmt.Sprintf("%v%v", baseIP, i)
		addr, err := netip.ParseAddr(targetStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing target %v -> %v", s, err)
		}
		bitlen := 32
		if addr.Is6() {
			bitlen = 128
		}
		IPPrefixes = append(IPPrefixes, netip.PrefixFrom(addr, bitlen))
	}

	return IPPrefixes, nil
}

func portsFromString(s string) ([]uint, error) {
	commaSeparatedPorts := strings.Split(s, ",")
	targetPorts := make([]uint, 0, 5)

	for _, portSpecString := range commaSeparatedPorts {
		if strings.ContainsRune(portSpecString, '-') {
			// Port Range Provided eg 10-20
			dashIndex := strings.LastIndex(portSpecString, "-")
			if dashIndex >= len(portSpecString) {
				return nil, fmt.Errorf("error parsing port range -> %v", portSpecString)
			}
			lower, err := strconv.Atoi(portSpecString[:dashIndex])
			if err != nil {
				return nil, fmt.Errorf("error parsing port range %v -> %v", portSpecString, err)
			}
			upper, err := strconv.Atoi(portSpecString[dashIndex+1:])
			if err != nil {
				return nil, fmt.Errorf("error parsing port range %v -> %v", portSpecString, err)
			}
			if lower > upper {
				return nil, fmt.Errorf("error parsing target %v -> invalid range", portSpecString)
			}
			for i := lower; i <= upper; i++ {
				targetPorts = append(targetPorts, uint(i))
			}
		} else {
			// Single port presumed
			portNum, err := strconv.Atoi(portSpecString)
			if err != nil {
				return nil, fmt.Errorf("error parsing port specification %v -> %v", portSpecString, err)
			}
			targetPorts = append(targetPorts, uint(portNum))
		}
	}

	slices.Sort(targetPorts)
	return netutils.Unique(targetPorts), nil
}
