package cmd

import (
	"time"

	"github.com/kakeetopius/gscn/cmd/scan"
	"github.com/spf13/cobra"
)

func ScanCmd() *cobra.Command {
	var scanOpts scan.ScanOpts

	scanCmd := cobra.Command{
		Use:     "scan <targets>",
		Short:   "Determine information about any host on any network for example open ports.",
		Aliases: []string{"s"},
		Args:    cobra.ExactArgs(1),
		Example: "\nTargets can be provided in the following formats:\n" +
			"  gscn scan 10.1.1.1 -p 80    # Single Host\n" +
			"  gscn scan 10.1.1.1/24 -p 80,90,100    # CIDR Notation\n" +
			"  gscn scan 10.1.1.1-5 -p 1-100    # IP Range\n" +
			"  gscn scan bing.com -p 1-100    # Domain Name\n" +
			"  gscn scan 10.1.1.1,bing.com,10.4.4.4-10,10.3.3.3/24 -p 1-100,433,8096 # Comma Separated List\n",
		RunE: func(cmd *cobra.Command, args []string) error {
			scanOpts.Notify = notify
			scanOpts.Config = config
			scanOpts.TargetsString = args[0]
			return scan.RunScan(scanOpts)
		},
	}

	scanCmd.Flags().SortFlags = false

	scanCmd.Flags().StringVarP(&scanOpts.PortsString, "ports", "p", "", "Specify a range of ports to scan for example 1-100 or 80,443,8080 or 1-100,443,8080")

	scanCmd.Flags().BoolVarP(&scanOpts.ResolveHostNames, "hostnames", "H", false, "Carry out a reverse lookup to get host names of the IP addresses given.")
	scanCmd.Flags().DurationVarP(&scanOpts.ResponseTimeout, "response-timeout", "T", 2*time.Second, "Amount of time to wait for responses")

	scanCmd.Flags().IntVarP(&scanOpts.Workers, "workers", "w", 64, "Number of workers to run concurrently when scanning with a maximum of 500")
	scanCmd.Flags().IntVar(&scanOpts.PingCount, "ping-count", 3, "Number of ICMP Echo Request packets to send when pinging")

	scanCmd.Flags().DurationVar(&scanOpts.PingTimeout, "ping-timeout", 0*time.Second, "Amount of time to wait for ping replies when doing scans.(Default is 1s times the ping count)")

	scanCmd.Flags().BoolVar(&scanOpts.SkipPingScan, "skip-ping", false, "Skip pinging hosts before scanning ports.")
	scanCmd.Flags().BoolVar(&scanOpts.DoUDPScan, "udp", false, "Carry out a UDP scan instead of default TCP scan. A ping scan is first carried out for each target.")
	scanCmd.Flags().BoolVar(&scanOpts.DoPingScan, "ping", false, "Carry out a ping scan to check if hosts are up.")

	scanCmd.Flags().BoolVar(&scanOpts.PrintOnlyOpen, "open", false, "Only show open and possibly filtered ports.")
	scanCmd.Flags().BoolVar(&scanOpts.PrintOnlyUp, "up", false, "Show results for only up hosts.")
	return &scanCmd
}
