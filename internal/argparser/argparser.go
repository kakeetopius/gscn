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
				MutuallyExclusiveFlags: []cli.MutuallyExclusiveFlags{
					{
						Flags: [][]cli.Flag{
							{
								&cli.StringFlag{
									Name:    "network",
									Aliases: []string{"n"},
									Usage:   "A network address with subnet mask in CIDR notation eg 10.10.10.1/24. For IPv6 the neighbor table of the host is queried",
								},
							},
							{
								&cli.StringFlag{
									Name:    "host",
									Aliases: []string{"H"},
									Usage:   "An IPv4 address of a host to find on the network. Same effect as using a /32(for ipv4) with -n option.",
								},
							},
						},
					},
				},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "iface",
						Aliases: []string{"i"},
						Usage:   "A network interface to find neighbouring hosts from. When used the entire subnet the interface is in is scanned.",
					},
					&cli.IntFlag{
						Name:    "timeout",
						Value:   2,
						Aliases: []string{"t"},
						Usage:   "Amount of time in seconds to wait for ARP responses.",
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
			},

			{
				Name:    "scan",
				Aliases: []string{"s"},
				Usage:   "determine information about any host on any network for example open ports.",
				MutuallyExclusiveFlags: []cli.MutuallyExclusiveFlags{
					{
						Required: true,
						Flags: [][]cli.Flag{
							{
								&cli.StringFlag{
									Name:    "network",
									Aliases: []string{"n"},
									Usage:   "A network address with subnet mask in CIDR notation eg 10.10.10.1/24",
								},
							},
							{
								&cli.StringFlag{
									Name:    "host",
									Aliases: []string{"H"},
									Usage:   "An IPv4 address of a host to scan",
								},
							},
						},
					},
				},

				Flags: []cli.Flag{
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
