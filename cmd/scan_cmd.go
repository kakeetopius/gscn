package cmd

import (
	"time"

	"github.com/kakeetopius/gscn/cmd/scan"
	"github.com/spf13/cobra"
)

var (
	ports           string
	workers         int
	responseTimeout time.Duration
	pingTimeout     time.Duration
	skipPing        bool
	doUDPScan       bool
	doPingScan      bool
)

func ScanCmd() *cobra.Command {
	scanCmd := cobra.Command{
		Use:     "scan",
		Short:   "Determine information about any host on any network for example open ports.",
		Aliases: []string{"s"},
		Example: "\nTargets can be provided in the following formats:\n" +
			"  gscn scan -t 10.1.1.1 -p 80    # Single Host\n" +
			"  gscn scan -t 10.1.1.1/24 -p 80,90,100    # CIDR Notation\n" +
			"  gscn scan -t 10.1.1.1-5 -p 1-100    # IP Range\n" +
			"  gscn scan -t bing.com -p 1-100    # Domain Name\n" +
			"  gscn scan -t 10.1.1.1,bing.com,10.4.4.4-10,10.3.3.3/24 -p 1-100,433,8096 	# Comma Separated List\n",
		RunE: func(cmd *cobra.Command, args []string) error {
			return scan.RunScan(scan.ScanOpts{
				Config:           config,
				TargetsString:    targetStr,
				PortsString:      ports,
				Workers:          workers,
				ResponseTimeout:  responseTimeout,
				PingTimeout:      pingTimeout,
				ResolveHostNames: resolveHostnames,
				DoPingScan:       doPingScan,
				DoUDPScan:        doUDPScan,
				SkipPingScan:     skipPing,
				Notify:           notify,
			})
		},
	}

	scanCmd.Flags().SortFlags = false

	scanCmd.Flags().StringVarP(&targetStr, "target", "t", "", "IP address(es) or hostname(s) of the host to scan.")
	scanCmd.Flags().StringVarP(&ports, "ports", "p", "", "Specify a range of ports to scan for example 1-100 or 80,443,8080 or 1-100,443,8080")

	scanCmd.Flags().IntVarP(&workers, "workers", "w", 64, "Number of workers to run concurrently when scanning with a maximum of 500")

	scanCmd.Flags().DurationVarP(&responseTimeout, "response-timeout", "T", 2*time.Second, "Amount of time to wait for responses")
	scanCmd.Flags().DurationVar(&pingTimeout, "ping-timeout", 2*time.Second, "Amount of time to wait for ping replies when doing scans.")

	scanCmd.Flags().BoolVarP(&resolveHostnames, "hostnames", "H", false, "Carry out a reverse lookup to get host names of the IP addresses given.")
	scanCmd.Flags().BoolVar(&skipPing, "skip-ping", false, "Skip pinging hosts before scanning ports.")
	scanCmd.Flags().BoolVar(&doUDPScan, "udp", false, "Carry out a UDP scan instead of default TCP scan. A ping scan is first carried out for each target.")
	scanCmd.Flags().BoolVar(&doPingScan, "ping", false, "Carry out a ping scan to check if hosts are up.")

	return &scanCmd
}
