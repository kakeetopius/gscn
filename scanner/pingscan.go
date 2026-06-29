package scanner

import (
	"context"
	"fmt"
	"html/template"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kakeetopius/gscn/internal/netutil"
	"github.com/kakeetopius/gscn/internal/notify"
	"github.com/prometheus-community/pro-bing"
	"github.com/pterm/pterm"
)

type PingScanner struct {
	PingScanOptions

	scanResults PingScanResults
	resultMap   PingScanResultsMap
}

type PingScanOptions struct {
	Targets             []netip.Prefix
	PingTimeout         time.Duration
	Workers             int
	AddUnknownHostNames bool
	HostNames           map[netip.Addr]string
	MessageNotifier     notify.Notifier
	PingCount           int
	SortResults         bool
	PrintOnlyUp         bool
}

type PingScanResults struct {
	HostResults []PingHostResult `json:"results"`
	PingStats   `json:"stats"`
}

type PingHostResult struct {
	IP         netip.Addr    `json:"ip"`
	HostName   string        `json:"hostname"`
	HostState  HostState     `json:"state"`
	AverageRTT time.Duration `json:"rtt"`
}

type PingStats struct {
	UpHosts    int           `json:"up"`
	DownHosts  int           `json:"down"`
	TotalHosts int           `json:"total_scanned"`
	ScanTime   time.Duration `json:"scan_duration"`
}

// PingScanResultsMap is an alternative result which stores the host results as a map indexed by ip addresses
type PingScanResultsMap map[netip.Addr]PingHostResult

type PingScanJob struct {
	Target    netip.Addr
	PingCount int
}

func NewPingScanner(opts PingScanOptions) *PingScanner {
	if opts.HostNames == nil {
		opts.HostNames = make(map[netip.Addr]string)
	}
	return &PingScanner{
		PingScanOptions: opts,
		resultMap:       make(map[netip.Addr]PingHostResult),
	}
}

func (s *PingScanner) Scan() error {
	startTime := time.Now()
	err := s.runPing()
	if err != nil {
		return err
	}
	endtime := time.Now()

	s.scanResults.ScanTime = endtime.Sub(startTime)

	if s.AddUnknownHostNames {
		spinner, _ := pterm.DefaultSpinner.Start("Resolving Host Names....")
		defer spinner.Success("Resolving Done")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for host, results := range s.resultMap {
			if results.HostName != "" {
				continue
			}

			name := netutil.ReverseLookup(ctx, host.String())
			results.HostName = name
			s.resultMap[host] = results
		}
	}

	s.sortResults()
	return err
}

func (s *PingScanner) SendResultsViaNotifier() error {
	if s.MessageNotifier == nil {
		return fmt.Errorf("pingscanner: no notifier is set")
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

	err = s.MessageNotifier.SendMessage(s.scanResults.String())
	if err != nil {
		return err
	}

	return nil
}

func (s *PingScanner) Results() ScanResults {
	return s.scanResults
}

func (s *PingScanner) ResultMap() PingScanResultsMap {
	return s.resultMap
}

func (s *PingScanner) SetNotifier(n notify.Notifier) {
	s.MessageNotifier = n
}

func (s *PingScanner) PrintResults() {
	printPingScanResults(s.scanResults, s.PrintOnlyUp)
}

func (s *PingScanner) sortResults() {
	resultMap := s.resultMap
	ipAddrs := make([]netip.Addr, 0, len(resultMap))

	for addr := range resultMap {
		ipAddrs = append(ipAddrs, addr)
	}

	slices.SortFunc(ipAddrs, func(a, b netip.Addr) int {
		return a.Compare(b)
	})

	sortedResults := make([]PingHostResult, 0, len(resultMap))
	for _, addr := range ipAddrs {
		sortedResults = append(sortedResults, resultMap[addr])
	}

	s.scanResults.HostResults = sortedResults
}

func (r PingScanResults) String() string {
	stringBuilder := strings.Builder{}

	tmpl := template.Must(template.New("ping_scan_results").Parse(PingScanResultsTemplate))
	tmpl.Execute(&stringBuilder, r)

	return stringBuilder.String()
}

func (s *PingScanner) runPing() error {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return fmt.Errorf("ping scan requires root permissions")
	}

	spinner, err := pterm.DefaultSpinner.Start("Pinging Hosts")
	if err != nil {
		return err
	}

	jobs := make(chan PingScanJob, s.Workers)
	workerResultsChan := make(chan PingHostResult, s.Workers)
	wg := &sync.WaitGroup{}
	for range s.Workers {
		wg.Add(1)
		go pingHost(s, wg, jobs, workerResultsChan)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scanResultsChan := make(chan PingScanResultsMap)
	// start workers
	go getPingScanResults(ctx, s, workerResultsChan, scanResultsChan)

	// send jobs
	for _, target := range s.Targets {
		IPaddr := target.Masked().Addr() // first IP in range
		for target.Contains(IPaddr) {
			jobs <- PingScanJob{
				Target:    IPaddr,
				PingCount: s.PingCount,
			}
			IPaddr = IPaddr.Next()
		}
	}

	close(jobs)
	wg.Wait()                // wait for all workers to finish
	close(workerResultsChan) // tell main worker to stop

	pingScanResults := <-scanResultsChan
	s.resultMap = pingScanResults
	spinner.Success("Pinging done")
	return nil
}

func pingHost(scanner *PingScanner, wg *sync.WaitGroup, jobs chan PingScanJob, resultChan chan PingHostResult) {
	// To be run by workers
	defer wg.Done()

	for job := range jobs {
		pinger := probing.New(job.Target.String())
		pinger.SetPrivileged(true)

		pinger.Count = job.PingCount
		pingTimeout := scanner.PingTimeout
		if pingTimeout == 0*time.Second {
			pingTimeout = 1 * time.Second
		}
		pinger.Timeout = pingTimeout

		pingResult := PingHostResult{
			HostState: HostStateDown,
			HostName:  scanner.HostNames[job.Target],
			IP:        job.Target,
		}
		err := pinger.Run()
		if err == nil {
			stats := pinger.Statistics()
			if stats.PacketsRecv > 0 {
				pingResult.HostState = HostStateUp
				pingResult.AverageRTT = stats.AvgRtt
			}
		}
		resultChan <- pingResult
	}
}

func getPingScanResults(ctx context.Context, scanner *PingScanner, workerResultsChan chan PingHostResult, scanResultsChan chan PingScanResultsMap) {
	// To Be Run By Main Worker (aggregator)
	scanResults := make(map[netip.Addr]PingHostResult)
	defer func() {
		scanResultsChan <- scanResults
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-workerResultsChan:
			if !ok {
				return // stop when channel is closed
			}
			scanner.scanResults.TotalHosts++
			switch result.HostState {
			case HostStateDown:
				scanner.scanResults.DownHosts++
			case HostStateUp:
				scanner.scanResults.UpHosts++
			}
			scanResults[result.IP] = result
		}
	}
}

func printPingScanResults(results PingScanResults, printUpOnly bool) {
	stats := results.PingStats

	var tableData [][]string
	tableData = pterm.TableData{{"Host", "State", "Average RTT"}}
	totalHosts := stats.TotalHosts
	for _, result := range results.HostResults {
		if result.HostState == HostStateDown && printUpOnly {
			continue
		}

		hostIdentity := result.IP.String()
		if result.HostState == HostStateDown && totalHosts > 256 {
			continue // do not add hosts that are down if scanned hosts are above 10
		}
		if result.HostName != "" {
			hostIdentity = fmt.Sprintf("%v (%v)", hostIdentity, result.HostName)
		}
		hostStateStyle := pterm.FgDefault
		switch result.HostState {
		case HostStateUp:
			hostStateStyle = pterm.FgGreen
		case HostStateDown:
			hostStateStyle = pterm.FgRed
		}
		tableData = append(tableData, []string{hostIdentity, hostStateStyle.Sprint(result.HostState), result.AverageRTT.Truncate(time.Microsecond).String()})
	}
	if len(tableData) > 1 {
		pterm.DefaultTable.WithHasHeader().WithBoxed().WithHeaderRowSeparator("-").WithData(tableData).Render()
	}
	fmt.Println("\nScan Duration:        ", stats.ScanTime.Truncate(time.Millisecond))
	fmt.Println("Total Hosts Scanned:  ", totalHosts)
	fmt.Println("Hosts that are Up:    ", stats.UpHosts)
	fmt.Printf("Hosts that are down:   %v\n\n", stats.DownHosts)
}
