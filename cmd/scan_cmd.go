package cmd

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/kakeetopius/gscn/internal/config"
	"github.com/kakeetopius/gscn/scanner"
	"github.com/spf13/cobra"
)

func ScanCmd() *cobra.Command {
	scanCmd := cobra.Command{
		Use:   "scan",
		Short: "Scan any host on any network.",
		Example: "\nTargets may be specified as individual IPv4/IPv6 addresses, IPv4/IPv6 CIDR ranges, Non-CIDR Ranges, domain names, or any combination of the above. e.g.\n" +
			"  gscn scan <scan-type> 10.1.1.1 -p 80\n" +
			"  gscn scan <scan-type> 2001:acad::1 -p 80\n" +
			"  gscn scan <scan-type> 10.1.1.1/24 -p 80,90,100\n" +
			"  gscn scan <scan-type> 10.1.1.1-5 -p 1-100\n" +
			"  gscn scan <scan-type> gscn.com -p 1-100\n" +
			"  gscn scan <scan-type> 2001:acad::1 10.1.1.1 -p 80\n" +
			"  gscn scan <scan-type> 10.1.1.1 gscn.com 10.4.4.4-10 10.3.3.3/24 -p 1-100,433,8096\n",
		Aliases: []string{"s"},
	}

	scanCmd.AddCommand(
		tcpFullScanCmd(),
		tcpSynScanCmd(),
		udpScanCmd(),
		pingScanCmd(),
	)

	return &scanCmd
}

func tcpFullScanCmd() *cobra.Command {
	var ports string

	opts := scanner.TCPFullScanOptions{}
	tcpCmd := cobra.Command{
		Use:   "tcp <targets>",
		Short: "Carry out a TCP full scan.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if opts.Workers > 500 {
				return fmt.Errorf("number of workers cannot go above 500")
			}
			opts.Targets, opts.HostNames, err = getScanTargets(args)
			if err != nil {
				return err
			}
			opts.TargetPorts, err = getPorts(ports)
			if err != nil {
				return err
			}

			appConfig, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			tcpScanner := scanner.NewTCPFullScanner(opts)

			return scanner.DoScan(tcpScanner, scanner.ScanOptions{
				ResultsOutputFile: outputFile,
				PrintJSON:         outputJSON,
				PrintJSONPretty:   jsonPretty,
				Notify:            sendNotification,
				Config:            appConfig,
			})
		},
	}

	tcpCmd.Flags().SortFlags = false
	tcpCmd.Flags().StringVarP(&ports, "ports", "p", "", "Specify a range of ports to scan for example 1-100 or 80,443,8080 or 1-100,443,8080")

	tcpCmd.Flags().BoolVarP(&opts.AddUnknownHostNames, "hostnames", "H", false, "Carry out a reverse lookup to get host names of the IP addresses given.")
	tcpCmd.Flags().DurationVarP(&opts.ResponseTimeout, "response-timeout", "t", 800*time.Millisecond, "Amount of time to wait for responses")

	tcpCmd.Flags().IntVarP(&opts.Workers, "workers", "w", 64, "Number of workers to run concurrently when scanning with a maximum of 500")
	tcpCmd.Flags().IntVar(&opts.PingCount, "ping-count", 3, "Number of ICMP Echo Request packets to send when pinging")

	tcpCmd.Flags().DurationVar(&opts.PingTimeout, "ping-timeout", 500*time.Millisecond, "Amount of time to wait for ping replies when doing scans.")

	tcpCmd.Flags().BoolVar(&opts.SkipPingScan, "skip-ping", false, "Skip pinging hosts before scanning ports.")

	tcpCmd.Flags().BoolVar(&opts.PrintOpenOnly, "open", false, "Only show open and possibly filtered ports.")
	tcpCmd.Flags().BoolVar(&opts.PrintUpOnly, "up", false, "Show results for only up hosts.")

	return &tcpCmd
}

func tcpSynScanCmd() *cobra.Command {
	var ports string

	opts := scanner.TCPSynScanOptions{}
	tcpCmd := cobra.Command{
		Use:   "syn <targets>",
		Short: "Carry out a TCP SYN scan.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if opts.Workers > 500 {
				return fmt.Errorf("number of workers cannot go above 500")
			}
			opts.Targets, opts.HostNames, err = getScanTargets(args)
			if err != nil {
				return err
			}
			opts.TargetPorts, err = getPorts(ports)
			if err != nil {
				return err
			}

			appConfig, err := config.Load(cfgFile)
			if err != nil {
				return err
			}
			synScanner, err := scanner.NewTCPSynScanner(opts)
			if err != nil {
				return err
			}

			return scanner.DoScan(synScanner, scanner.ScanOptions{
				ResultsOutputFile: outputFile,
				PrintJSON:         outputJSON,
				PrintJSONPretty:   jsonPretty,
				Notify:            sendNotification,
				Config:            appConfig,
			})
		},
	}

	tcpCmd.Flags().SortFlags = false
	tcpCmd.Flags().StringVarP(&ports, "ports", "p", "", "Specify a range of ports to scan for example 1-100 or 80,443,8080 or 1-100,443,8080")

	tcpCmd.Flags().BoolVarP(&opts.AddUnknownHostNames, "hostnames", "H", false, "Carry out a reverse lookup to get host names of the IP addresses given.")
	tcpCmd.Flags().DurationVarP(&opts.ResponseTimeout, "response-timeout", "t", 800*time.Millisecond, "Amount of time to wait for responses")

	tcpCmd.Flags().IntVarP(&opts.Workers, "workers", "w", 64, "Number of workers to run concurrently when scanning with a maximum of 500")
	tcpCmd.Flags().IntVar(&opts.PingCount, "ping-count", 3, "Number of ICMP Echo Request packets to send when pinging")

	tcpCmd.Flags().DurationVar(&opts.PingTimeout, "ping-timeout", 500*time.Millisecond, "Amount of time to wait for ping replies when doing scans.")

	tcpCmd.Flags().BoolVar(&opts.PrintOpenOnly, "open", false, "Only show open and possibly filtered ports.")
	tcpCmd.Flags().BoolVar(&opts.PrintUpOnly, "up", false, "Show results for only up hosts.")

	return &tcpCmd
}

func udpScanCmd() *cobra.Command {
	var ports string

	var opts scanner.UDPScanOptions
	udpCmd := cobra.Command{
		Use:   "udp <targets>",
		Short: "Carry out a udp scan",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Workers > 500 {
				return fmt.Errorf("number of workers cannot go above 500")
			}

			var err error
			opts.Targets, opts.HostNames, err = getScanTargets(args)
			if err != nil {
				return err
			}
			opts.TargetPorts, err = getPorts(ports)
			if err != nil {
				return err
			}

			appConfig, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			udpScanner := scanner.NewUDPScanner(opts)
			return scanner.DoScan(udpScanner, scanner.ScanOptions{
				ResultsOutputFile: outputFile,
				PrintJSON:         outputJSON,
				PrintJSONPretty:   jsonPretty,
				Notify:            sendNotification,
				Config:            appConfig,
			})
		},
	}
	udpCmd.Flags().SortFlags = false
	udpCmd.Flags().StringVarP(&ports, "ports", "p", "", "Specify a range of ports to scan for example 1-100 or 80,443,8080 or 1-100,443,8080")

	udpCmd.Flags().BoolVarP(&opts.AddUnknownHostNames, "hostnames", "H", false, "Carry out a reverse lookup to get host names of the IP addresses given.")
	udpCmd.Flags().DurationVarP(&opts.ResponseTimeout, "response-timeout", "t", 800*time.Millisecond, "Amount of time to wait for responses")

	udpCmd.Flags().IntVarP(&opts.Workers, "workers", "w", 64, "Number of workers to run concurrently when scanning with a maximum of 500")
	udpCmd.Flags().IntVar(&opts.PingCount, "ping-count", 3, "Number of ICMP Echo Request packets to send when pinging")

	udpCmd.Flags().DurationVar(&opts.PingTimeout, "ping-timeout", 500*time.Millisecond, "Amount of time to wait for ping replies when doing scans.")

	udpCmd.Flags().BoolVar(&opts.PrintOpenOnly, "open", false, "Only show open and possibly filtered ports.")
	udpCmd.Flags().BoolVar(&opts.PrintUpOnly, "up", false, "Show results for only up hosts.")

	return &udpCmd
}

func pingScanCmd() *cobra.Command {
	var opts scanner.PingScanOptions
	pingCmd := cobra.Command{
		Use:   "ping <targets>",
		Short: "Carry out a ping scan",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Workers > 500 {
				return fmt.Errorf("number of workers cannot go above 500")
			}

			var err error
			opts.Targets, opts.HostNames, err = getScanTargets(args)
			if err != nil {
				return err
			}
			opts.SortResults = true

			appConfig, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			pingScanner := scanner.NewPingScanner(opts)
			return scanner.DoScan(pingScanner, scanner.ScanOptions{
				ResultsOutputFile: outputFile,
				PrintJSON:         outputJSON,
				PrintJSONPretty:   jsonPretty,
				Notify:            sendNotification,
				Config:            appConfig,
			})
		},
	}

	pingCmd.Flags().SortFlags = false
	pingCmd.Flags().BoolVarP(&opts.AddUnknownHostNames, "hostnames", "H", false, "Carry out a reverse lookup to get host names of the IP addresses given.")

	pingCmd.Flags().IntVarP(&opts.Workers, "workers", "w", 64, "Number of workers to run concurrently when scanning with a maximum of 500")
	pingCmd.Flags().IntVarP(&opts.PingCount, "count", "c", 4, "Number of ICMP Echo Request packets to send when pinging")

	pingCmd.Flags().DurationVarP(&opts.PingTimeout, "timeout", "t", 2*time.Second, "Amount of time to wait for ping replies when doing scans.")

	pingCmd.Flags().BoolVar(&opts.PrintOnlyUp, "up", false, "Show results for only up hosts.")
	return &pingCmd
}

// getScanTargets takes strings of targets and returns a slice of netip.Prefixes and a map of netip.Addr to hostnames.
// It also returns an error if there are no targets provided or if there is an error parsing the targets.
func getScanTargets(targetStrs []string) ([]netip.Prefix, map[netip.Addr]string, error) {
	var targets []netip.Prefix
	var err error

	var hostNames map[netip.Addr]string

	if len(targetStrs) != 0 {
		targets, hostNames, err = scanner.TargetsFromStringWithDNSLookup(targetStrs)
		if err != nil {
			return nil, nil, err
		}
	}

	if len(targets) == 0 {
		return nil, nil, fmt.Errorf("no hosts to scan provided")
	}

	return targets, hostNames, nil
}

// getPorts takes a string of comma separated ports and returns a slice of the port numbers as uints. It also returns an error if there is an error parsing the ports.
func getPorts(portString string) (ports []scanner.PortNumber, err error) {
	if portString == "" {
		return
	}

	ports, err = scanner.PortsFromString(portString)
	if err != nil {
		return nil, err
	}

	return
}
