// Package argparser provides command-line parsing utilites for subcommands
package argparser

import (
	"context"
	"errors"
	"fmt"

	"github.com/kakeetopius/gscn/internal/net/discover"
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
					&cli.IntFlag{
						Name:    "timeout",
						Value:   2,
						Aliases: []string{"T"},
						Usage:   "Amount of time in seconds to wait for responses.",
					},
					&cli.BoolFlag{
						Name:    "reverse",
						Value:   false,
						Aliases: []string{"r"},
						Usage:   "Carry out a reverse lookup on the IP addresses discovered on the network.",
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
						Usage:   "IP address(s) of the host to scan. Can be in CIDR notation eg 10.1.1.1/24 or as a list 10.1.1.1,10.1.1.2 or both 10.1.1.1/24,10.2.2.2",
					},
					&cli.StringFlag{
						Name:    "iface",
						Aliases: []string{"i"},
						Usage:   "A network interface to scan hosts from.",
					},
					&cli.IntFlag{
						Name:    "timeout",
						Aliases: []string{"t"},
						Usage:   "Amount of time in seconds to scan for.",
					},
					&cli.IntFlag{
						Name:    "port",
						Aliases: []string{"p"},
						Usage:   "A port to check if open",
					},
					&cli.StringFlag{
						Name:    "port-range",
						Aliases: []string{"port-range"},
						Usage:   "Specify a range of ports to scan for example 1-100 or 80,443,8080 or 1-100,443,8080",
					},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					fmt.Println("Running a scan")
					return nil
				},
			},
		},
	}
}
