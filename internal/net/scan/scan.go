// Package scan is used to get various network information about hosts on a network.
package scan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/kakeetopius/gscn/internal/netutils"
	"github.com/urfave/cli/v3"
)

type ScanOptions struct {
	TargetHosts []netip.Prefix
	TargetPorts []uint8
	Timeout     int
}

type PortState uint8

const (
	PortStateOpen PortState = iota
	PortStateClosed
)

type Port struct {
	Number uint
	State  PortState
}

type ScanResult struct {
	Target netip.Addr
	Port   Port
}

type ScanResults map[netip.Addr][]Port

func RunScan(clictx context.Context, cmd *cli.Command) error {
	// var opts ScanOptions
	var err error
	targets := make([]netip.Prefix, 0)
	ports := make([]uint, 0)

	// opts.Timeout = cmd.Int("timeout")

	if targetStr := cmd.String("target"); targetStr != "" {
		targets, err = netutils.TargetsFromString(targetStr)
		if err != nil {
			return err
		}
	}
	if portStr := cmd.String("ports"); portStr != "" {
		ports, err = netutils.PortsFromString(portStr)
		if err != nil {
			return err
		}
	}

	jobs := make(chan netip.AddrPort, 64)
	workerResultsChan := make(chan ScanResult, 64)
	wg := &sync.WaitGroup{}
	for range 64 {
		wg.Add(1)
		go ScanHostPort(wg, jobs, workerResultsChan)
	}

	for _, target := range targets {
		for _, port := range ports {
			targetAddrPort := netip.AddrPortFrom(target.Addr(), uint16(port))
			jobs <- targetAddrPort
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	scanResultsChan := make(chan ScanResults)
	go getScanResults(ctx, workerResultsChan, scanResultsChan)

	close(jobs) // stops the for loop in workers
	wg.Wait()   // wait for all to workers to exit
	cancel()    // tell the main Worker to stop and send results

	scanResults := <-scanResultsChan
	PrintScanResults(scanResults)
	return nil
}

func getScanResults(ctx context.Context, workerResultsChan chan ScanResult, scanResultsChan chan ScanResults) {
	scanResults := make(ScanResults)
	for {
		select {
		case <-ctx.Done():
			scanResultsChan <- scanResults
			return
		case result := <-workerResultsChan:
			scanResults[result.Target] = append(scanResults[result.Target], result.Port)
		}
	}
}

func ScanHostPort(wg *sync.WaitGroup, jobs chan netip.AddrPort, resultsChan chan<- ScanResult) {
	for target := range jobs {
		tcpAddr := net.TCPAddr{
			IP:   target.Addr().AsSlice(),
			Port: int(target.Port()),
		}
		_, err := net.DialTCP("tcp", nil, &tcpAddr)

		result := ScanResult{
			Target: target.Addr(),
			Port: Port{
				Number: uint(target.Port()),
			},
		}
		if err != nil {
			result.Port.State = PortStateClosed
		} else {
			result.Port.State = PortStateOpen
		}

		resultsChan <- result
	}
	wg.Done()
}

func PrintScanResults(results ScanResults) {
	for target, ports := range results {
		fmt.Printf("Scan Results for %v\n", target)
		for _, port := range ports {
			var state string
			if port.State == PortStateOpen {
				state = "open"
			} else {
				state = "closed"
			}
			fmt.Printf("Port %v: %v\n", port.Number, state)
		}
	}
}
