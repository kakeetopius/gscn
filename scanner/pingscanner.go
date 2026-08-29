package scanner

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/kakeetopius/gscn/internal/netutil"
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
	PingCount           int
	SortResults         bool
	ResultMapOnly       bool
	PrintOnlyUp         bool
}

type PingScanResults struct {
	HostResults []PingHostResult `json:"results"`
	PingStats   `json:"stats"`

	printUpOnly bool `json:"-"`
}

type PingHostResult struct {
	IP             netip.Addr    `json:"ip"`
	HostName       string        `json:"hostname"`
	HostState      HostState     `json:"state"`
	AverageRTT     time.Duration `json:"rtt"`
	PacketsSent    int
	PacketReceived int
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

func (s *PingScanner) Scan(ctx context.Context) (ScanResults, error) {
	startTime := time.Now()
	err := s.runPing(ctx)
	if err != nil {
		return nil, err
	}

	s.scanResults.ScanTime = time.Since(startTime)
	s.scanResults.printUpOnly = s.PrintOnlyUp

	s.processResults()

	if !s.ResultMapOnly {
		s.scanResults.HostResults = resultMapToSlice(s.resultMap, s.SortResults)
	}

	return &s.scanResults, err
}

func (s *PingScanner) processResults() {
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
}

func (s *PingScanner) ResultMap() PingScanResultsMap {
	return s.resultMap
}

func resultMapToSlice(m PingScanResultsMap, sort bool) []PingHostResult {
	var ipAddrs iter.Seq[netip.Addr]

	if sort {
		ips := make([]netip.Addr, 0, len(m))
		for addr := range m {
			ips = append(ips, addr)
		}

		slices.SortFunc(ips, func(a, b netip.Addr) int {
			return a.Compare(b)
		})
		ipAddrs = func(yield func(netip.Addr) bool) {
			for _, addr := range ips {
				if !yield(addr) {
					return
				}
			}
		}
	} else {
		ipAddrs = maps.Keys(m)
	}

	results := make([]PingHostResult, 0, len(m))
	for addr := range ipAddrs {
		results = append(results, m[addr])
	}

	return results
}

func (r *PingScanResults) Print() {
	r.display()
}

func (r PingScanResults) String() string {
	stringBuilder := strings.Builder{}

	tmpl := template.Must(template.New("ping_scan_results").Parse(PingScanResultsTemplate))
	tmpl.Execute(&stringBuilder, r)

	return stringBuilder.String()
}

func (s *PingScanner) runPing(ctx context.Context) error {
	if s.Workers <= 0 {
		return fmt.Errorf("invalid number of workers")
	}
	spinner, err := pterm.DefaultSpinner.Start("Pinging Hosts")
	if err != nil {
		return err
	}

	jobs := make(chan PingScanJob, s.Workers)
	workerResultsChan := make(chan PingHostResult, s.Workers)
	wg := &sync.WaitGroup{}
	// start workers
	for range s.Workers {
		wg.Add(1)
		go pingHost(s, wg, jobs, workerResultsChan)
	}

	masterDone := make(chan struct{})
	go s.getPingScanResults(ctx, workerResultsChan, masterDone)

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
	wg.Wait() // wait for all workers to finish

	close(workerResultsChan)
	<-masterDone // wait for master to finish

	spinner.Success("Pinging done")
	return nil
}

func pingHost(scanner *PingScanner, wg *sync.WaitGroup, jobs chan PingScanJob, resultChan chan PingHostResult) {
	// To be run by workers
	setprivileged := true

	defer wg.Done()

	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		setprivileged = false
	}

	for job := range jobs {
		pinger := probing.New(job.Target.String())
		pinger.SetPrivileged(setprivileged)

		pinger.Count = job.PingCount
		pingTimeout := scanner.PingTimeout
		if pingTimeout == 0*time.Second {
			pingTimeout = time.Second * time.Duration(scanner.PingCount)
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
			pingResult.PacketsSent = stats.PacketsSent
			if stats.PacketsRecv > 0 {
				pingResult.HostState = HostStateUp
				pingResult.AverageRTT = stats.AvgRtt
				pingResult.PacketReceived = stats.PacketsRecv
			}
		}
		resultChan <- pingResult
	}
}

func (s *PingScanner) getPingScanResults(ctx context.Context, workerResultsChan chan PingHostResult, masterDone chan struct{}) {
	// To Be Run By Main Worker (aggregator)
	if s.resultMap == nil {
		s.resultMap = make(map[netip.Addr]PingHostResult)
	}
	defer func() {
		masterDone <- struct{}{}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-workerResultsChan:
			if !ok {
				return // stop when channel is closed
			}
			s.scanResults.TotalHosts++
			switch result.HostState {
			case HostStateDown:
				s.scanResults.DownHosts++
			case HostStateUp:
				s.scanResults.UpHosts++
			}
			s.resultMap[result.IP] = result
		}
	}
}

func (r PingScanResults) display() {
	stats := r.PingStats

	var tableData [][]string
	tableData = pterm.TableData{{"Host", "State", "Sent", "Recvd", "Average RTT"}}
	totalHosts := stats.TotalHosts
	for _, result := range r.HostResults {
		if result.HostState == HostStateDown && r.printUpOnly {
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
		tableData = append(tableData, []string{
			hostIdentity,
			hostStateStyle.Sprint(result.HostState),
			strconv.Itoa(result.PacketsSent),
			strconv.Itoa(result.PacketReceived),
			result.AverageRTT.Truncate(time.Microsecond).String(),
		})
	}
	if len(tableData) > 1 {
		pterm.DefaultTable.WithHasHeader().WithBoxed().WithHeaderRowSeparator("-").WithData(tableData).Render()
	}
	fmt.Println("\nScan Duration:        ", stats.ScanTime.Truncate(time.Millisecond))
	fmt.Println("Total Hosts Scanned:  ", totalHosts)
	fmt.Println("Hosts that are Up:    ", stats.UpHosts)
	fmt.Printf("Hosts that are down:   %v\n\n", stats.DownHosts)
}
