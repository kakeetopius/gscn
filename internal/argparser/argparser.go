// Package argparser provides command-line parsing utilites for subcommands
package argparser

import (
	"errors"
	"fmt"

	"github.com/kakeetopius/gscn/internal/net/discover"
	"github.com/spf13/pflag"
)

var ErrHelp = errors.New("user requested help")

func ParseArgs(args []string) (*Command, error) {
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		GeneralUsage()
		return nil, ErrHelp
	}

	inputCommand, err := getCommand(args[0])
	if err != nil {
		GeneralUsage()
		return nil, err
	}

	argMap, flags, err := inputCommand.argParser(args)
	inputCommand.addArgs(argMap, flags)
	return inputCommand, err
}

func discoverArgParser(opts []string) (map[string]string, int, error) {
	discoverFs := pflag.NewFlagSet("discover", pflag.ContinueOnError)
	discoverFs.Usage = discoverUsage
	flags := 0

	netStr := discoverFs.StringP("network", "n", "", "")
	hostStr := discoverFs.StringP("host", "H", "", "")
	ifaceStr := discoverFs.StringP("iface", "i", "", "")
	reverseLookup := discoverFs.BoolP("reverse", "r", false, "")
	ipv6 := discoverFs.BoolP("six", "6", false, "")
	timeout := discoverFs.StringP("timeout", "t", "", "")

	if len(opts) < 2 {
		discoverFs.Usage()
		return nil, 0, fmt.Errorf("no option given")
	}

	err := discoverFs.Parse(opts[1:])
	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return nil, 0, ErrHelp
		}
		discoverFs.Usage()
		return nil, 0, err
	}
	if len(discoverFs.Args()) > 0 {
		return nil, 0, fmt.Errorf("unexpected argument(s): %v", discoverFs.Args())
	}

	argValues := make(map[string]string, 4)
	if discoverFs.Changed("network") {
		argValues["network"] = *netStr
	}
	if discoverFs.Changed("host") {
		argValues["host"] = *hostStr
	}
	if discoverFs.Changed("iface") {
		argValues["iface"] = *ifaceStr
	}
	if discoverFs.Changed("timeout") {
		argValues["timeout"] = *timeout
	}

	if *reverseLookup {
		flags |= discover.DoReverseLookup
	}
	if *ipv6 {
		flags |= discover.DoIPv6AddressResolution
	}
	return argValues, flags, nil
}

func scanArgParser(opts []string) (map[string]string, int, error) {
	scanFs := pflag.NewFlagSet("scan", pflag.ContinueOnError)
	scanFs.Usage = scanUsage

	if len(opts) < 2 {
		scanFs.Usage()
		return nil, 0, fmt.Errorf("no option given")
	}

	netStr := scanFs.StringP("network", "n", "", "")
	hostStr := scanFs.StringP("host", "H", "", "")
	ifaceStr := scanFs.StringP("iface", "i", "", "")
	list := scanFs.StringP("list", "l", "", "")
	portStr := scanFs.StringP("port", "p", "", "")
	portRangeStr := scanFs.StringP("port-range", "P", "", "")

	err := scanFs.Parse(opts[1:])
	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return nil, 0, ErrHelp
		}
		scanFs.Usage()
		return nil, 0, err
	}
	if len(scanFs.Args()) > 0 {
		return nil, 0, fmt.Errorf("unexpected argument(s): %v", scanFs.Args())
	}

	argValues := make(map[string]string, 6)
	if scanFs.Changed("network") {
		argValues["network"] = *netStr
	}
	if scanFs.Changed("host") {
		argValues["host"] = *hostStr
	}
	if scanFs.Changed("iface") {
		argValues["iface"] = *ifaceStr
	}
	if scanFs.Changed("list") {
		argValues["list"] = *list
	}
	if scanFs.Changed("port") {
		argValues["port"] = *portStr
	}
	if scanFs.Changed("port-range") {
		argValues["port-range"] = *portRangeStr
	}

	return argValues, 0, nil
}
