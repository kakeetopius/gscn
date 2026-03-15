// Package argparser provides command-line parsing utilites for subcommands
package argparser

import (
	"errors"
	"time"

	"github.com/kakeetopius/gscn/internal/cli/discover"
	"github.com/kakeetopius/gscn/internal/cli/scan"
	"github.com/urfave/cli/v3"
)

var ErrHelp = errors.New("user requested help")

// GetCommand returns a command struct containing the context about the command line flags and arguments the user has passed.
func GetCommand() *cli.Command {
	return &cli.Command{
		Name:                  "gscn",
		Usage:                 "A simple command line tool to carry out different operations on a network.",
		Authors:               []any{"Kakeeto Pius"},
		EnableShellCompletion: true,

		Commands: []*cli.Command{
			{
				Name:    "discover",
				Aliases: []string{"d"},
				Usage:   "discover hosts on the local network using ARP for IPv4 or ICMP Neighbour Discovery for IPv6.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "target",
						Aliases: []string{"t"},
						Usage:   "IP address(es) of the host to scan.",
					},
					&cli.StringFlag{
						Name:    "iface",
						Aliases: []string{"i"},
						Usage:   "A network interface to find neighbouring hosts from. When used without a target the entire subnet the interface is in is scanned.",
					},
					&cli.StringFlag{
						Name:    "source",
						Aliases: []string{"S"},
						Usage:   "Source IP Address to put in the solicting packets.",
					},
					&cli.DurationFlag{
						Name:    "timeout",
						Value:   2 * time.Second,
						Aliases: []string{"T"},
						Usage:   "Amount of time in seconds to wait for responses.",
					},
					&cli.BoolFlag{
						Name:    "hostnames",
						Value:   false,
						Aliases: []string{"H"},
						Usage:   "Carry out a reverse lookup on the IP addresses discovered on the network to get their host names",
					},
					&cli.BoolFlag{
						Name:    "six",
						Value:   false,
						Aliases: []string{"s"},
						Usage:   "Use IPv6's ICMP Neighbor discovery instead of ARP.",
					},
				},

				Action: discover.RunDiscover,
				Description: "Targets can be provided in the following formats:\n" +
					"\tgscn discover -t 10.1.1.1 # Single Host\n" +
					"\tgscn discover -t 10.1.1.1/24 # CIDR Notation\n" +
					"\tgscn discover -t 10.1.1.1-5 # IP Range\n" +
					"\tgscn discover -t 10.1.1.1,10.2.2.2/24,10.4.4.4-10 # Comma Separated List\n",
			},

			{
				Name:    "scan",
				Aliases: []string{"s"},
				Usage:   "determine information about any host on any network for example open ports.",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "target",
						Aliases: []string{"t"},
						Usage:   "IP address(es) of the host to scan.",
					},
					&cli.StringFlag{
						Name:    "ports",
						Aliases: []string{"p"},
						Usage:   "Specify a range of ports to scan for example 1-100 or 80,443,8080 or 1-100,443,8080",
					},
					&cli.BoolFlag{
						Name:    "udp",
						Aliases: []string{"u"},
						Usage:   "Carry out a UDP scan instead of default TCP scan",
					},
					&cli.BoolFlag{
						Name:    "hostnames",
						Value:   false,
						Aliases: []string{"H"},
						Usage:   "Carry out a reverse lookup to get host names on the IP addresses given.",
					},
					&cli.IntFlag{
						Name:    "timeout",
						Value:   2,
						Aliases: []string{"T"},
						Usage:   "Amount of time in seconds to scan for.",
					},
					&cli.IntFlag{
						Name:    "workers",
						Aliases: []string{"w"},
						Value:   64,
						Usage:   "Number of workers to run concurrently when scanning with a maximum of 500",
					},
				},
				Description: "Targets can be provided in the following formats:\n" +
					"\tgscn scan -t 10.1.1.1 -p 80    # Single Host\n" +
					"\tgscn scan -t 10.1.1.1/24 -p 80,90,100    # CIDR Notation\n" +
					"\tgscn scan -t 10.1.1.1-5 -p 1-100    # IP Range\n" +
					"\tgscn scan -t bing.com -p 1-100    # Domain Name\n" +
					"\tgscn scan -t 10.1.1.1,bing.com,10.4.4.4-10,10.3.3.3/24 -p 1-100,433,8096 	# Comma Separated List\n",
				Action: scan.RunScan,
			},
		},
	}
}
