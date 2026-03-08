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
	"unicode"

	"github.com/google/gopacket/layers"
	"github.com/kakeetopius/gscn/internal/netutils"
	"github.com/pterm/pterm"
	"github.com/urfave/cli/v3"
)

type ScanTarget struct {
	Address netip.Addr
	Port    Port
}

type ScanOptions struct {
	TargetHosts []ScanTarget
	TargetPorts []uint
	Timeout     int
	Scanner     func(opts *ScanOptions, wg *sync.WaitGroup, jobs chan ScanTarget, resultsChan chan<- WorkerResult)
}

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

type HostResult struct {
	Ports       []Port
	OpenPorts   int
	ClosedPorts int
}

type WorkerResult struct {
	HostIP netip.Addr
	Port   Port
}

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
		targets, err = scanTargetFromString(targetStr)
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

	jobs := make(chan ScanTarget, numWorkers)
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
	for _, target := range targets {
		for _, port := range ports {
			target.Port = Port{Number: port}
			jobs <- target
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	scanResultsChan := make(chan ScanResults)
	go getScanResults(ctx, workerResultsChan, scanResultsChan)

	close(jobs) // stops the for loop in workers
	wg.Wait()   // wait for all to workers to exit
	cancel()    // tell the main Woker to stop and send results

	spinner.Success("Done")
	scanResults := <-scanResultsChan
	addScanStats(scanResults)
	PrintScanResults(scanResults)
	return nil
}

func getScanResults(ctx context.Context, workerResultsChan chan WorkerResult, scanResultsChan chan ScanResults) {
	scanResults := make(ScanResults)
	for {
		select {
		case <-ctx.Done():
			scanResultsChan <- scanResults
			return
		case result := <-workerResultsChan:
			hostIP := result.HostIP
			hostResults := scanResults[hostIP]
			hostResults.Ports = append(hostResults.Ports, result.Port)
			scanResults[hostIP] = hostResults
		}
	}
}

func ScanHostTCPPort(opts *ScanOptions, wg *sync.WaitGroup, jobs chan ScanTarget, resultsChan chan<- WorkerResult) {
	for target := range jobs {
		tcpAddr := net.TCPAddr{
			IP:   target.Address.AsSlice(),
			Port: int(target.Port.Number),
		}
		proto := ""
		if target.Address.Is4() {
			proto = "tcp"
		} else {
			proto = "tcp6"
		}
		_, err := net.DialTCP(proto, nil, &tcpAddr)

		result := WorkerResult{
			HostIP: target.Address,
			Port: Port{
				Number:   uint(target.Port.Number),
				Protocol: proto,
			},
		}
		if err != nil {
			result.Port.State = PortStateClosed
		} else {
			result.Port.State = PortStateOpen
			result.Port.Name = serviceFromString(layers.TCPPort(target.Port.Number).String())
		}

		resultsChan <- result
	}
	wg.Done()
}

func ScanHostUDPPort(opts *ScanOptions, wg *sync.WaitGroup, jobs chan ScanTarget, resultsChan chan<- WorkerResult) {
	for target := range jobs {
		udpAddr := net.UDPAddr{
			IP:   target.Address.AsSlice(),
			Port: int(target.Port.Number),
		}
		proto := ""
		if target.Address.Is4() {
			proto = "udp"
		} else {
			proto = "udp6"
		}
		result := WorkerResult{
			HostIP: target.Address,
			Port: Port{
				Number:   uint(target.Port.Number),
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
		conn.Write(buf) // first write to the connection so we can responses if any
		_, err = conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// if we got a timeout, it can be because the port is filtered or open but silent
				result.Port.State = PortStatePossibleFilter
				result.Port.Name = serviceFromString(layers.UDPPort(target.Port.Number).String())
			} else {
				// any other error means the port is closed
				result.Port.State = PortStateClosed
			}
		} else {
			result.Port.State = PortStateOpen
			result.Port.Name = serviceFromString(layers.UDPPort(target.Port.Number).String())
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
			tcpService := serviceFromString(layers.TCPPort(port.Number).String())
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

func serviceFromString(s string) string {
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

func addScanStats(results ScanResults) {
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

func scanTargetFromString(s string) ([]ScanTarget, error) {
	// Example: 10.1.1.1/24,10.1.1.1,bing.com,10.1.1.1-2,google.com
	commaSeparatedTargets := strings.Split(s, ",")
	targets := make([]ScanTarget, 0, 5)

	for _, targetString := range commaSeparatedTargets {
		if unicode.IsLetter([]rune(targetString)[0]) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			resolver := net.Resolver{}
			names, err := resolver.LookupIP(ctx, "ip4", targetString)
			if err == nil && len(names) > 0 {
				addr, ok := netip.AddrFromSlice(names[0])
				if !ok {
					return nil, fmt.Errorf("error looking up IP for target %v", targetString)
				}
				targets = append(targets, ScanTarget{
					Address: addr,
				})
				HostNames[addr] = targetString
			} else if err != nil {
				return nil, fmt.Errorf("error looking up IP for target %v -> %v", targetString, err)
			}
		} else if strings.ContainsRune(targetString, '/') {
			network, err := netip.ParsePrefix(targetString)
			addr := network.Masked().Addr().Next()
			for network.Contains(addr) {
				targets = append(targets, ScanTarget{Address: addr})
				addr = addr.Next()
			}
			if err != nil {
				return nil, fmt.Errorf("error parsing target %v -> %v", targetString, err)
			}
		} else if strings.ContainsRune(targetString, '-') {
			dashIndex := strings.LastIndex(targetString, "-")
			if dashIndex >= len(targetString) {
				return nil, fmt.Errorf("error parsing target -> %v", targetString)
			}
			lastDotIndex := strings.LastIndex(targetString, ".")
			if lastDotIndex == -1 {
				return nil, fmt.Errorf("error parsing -> %v", targetString)
			}
			baseIP := targetString[:lastDotIndex+1]
			lower, err := strconv.Atoi(targetString[lastDotIndex+1 : dashIndex])
			if err != nil {
				return nil, fmt.Errorf("error parsing target %v -> %v", targetString, err)
			}
			upper, err := strconv.Atoi(targetString[dashIndex+1:])
			if err != nil {
				return nil, fmt.Errorf("error parsing target %v -> %v", targetString, err)
			}
			if lower > upper {
				return nil, fmt.Errorf("error parsing target %v -> invalid range", targetString)
			} else if upper >= 256 {
				return nil, fmt.Errorf("error parsing target %v -> range cannot go above 255", targetString)
			} else if lower < 0 {
				return nil, fmt.Errorf("error parsing target %v -> range cannot be below zero", targetString)
			}

			for i := lower; i <= upper; i++ {
				targetStr := fmt.Sprintf("%v%v", baseIP, i)
				addr, err := netip.ParseAddr(targetStr)
				if err != nil {
					return nil, fmt.Errorf("error parsing target %v -> %v", targetString, err)
				}
				targets = append(targets, ScanTarget{Address: addr})
			}
		} else {
			addr, err := netip.ParseAddr(targetString)
			if err != nil {
				return nil, fmt.Errorf("error parsing target %v -> %v", targetString, err)
			}
			targets = append(targets, ScanTarget{Address: addr})
		}
	}

	return netutils.Unique(targets), nil
}

func portsFromString(s string) ([]uint, error) {
	commaSeparatedPorts := strings.Split(s, ",")
	targetPorts := make([]uint, 0, 5)

	for _, portSpecString := range commaSeparatedPorts {
		if strings.ContainsRune(portSpecString, '-') {
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
