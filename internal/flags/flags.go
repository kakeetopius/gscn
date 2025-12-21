// Package flags provides command-line parsing utilites for subcommands
package flags

import (
	"errors"
	"fmt"

	"github.com/kakeetopius/gohunter/internal/net/find"
	"github.com/kakeetopius/gohunter/internal/net/scan"
	"github.com/spf13/pflag"
)

type Runner func(map[string]string) error

type Command struct {
	Name      string
	Arguments map[string]string
	Flags     int
	argParser func([]string) (map[string]string, int, error)
	cmdRun    Runner
}

var commands = map[string]Command{
	"find": {Name: "find", argParser: findArgParser, cmdRun: find.RunFind},
	"scan": {Name: "scan", argParser: scanArgParser, cmdRun: scan.RunScan},
}

var ErrHelp = errors.New("user requested help")

func (c *Command) Run() {
	c.cmdRun(c.Arguments)
}

func (c *Command) addArgs(args map[string]string, flags int) {
	c.Arguments = args
	c.Flags = flags
}

func ParseArgs(args []string) (Command, error) {
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		GeneralUsage()
		return Command{}, ErrHelp
	}

	inputCommand, found := commands[args[0]]
	if !found {
		GeneralUsage()
		return Command{}, fmt.Errorf("unknown subcommand: %v", args[0])
	}

	argMap, flags, err := inputCommand.argParser(args)
	inputCommand.addArgs(argMap, flags)
	return inputCommand, err
}

func findArgParser(opts []string) (map[string]string, int, error) {
	findFs := pflag.NewFlagSet("find", pflag.ContinueOnError)
	findFs.Usage = findUsage

	netStr := findFs.StringP("network", "n", "", "")
	hostStr := findFs.StringP("host", "H", "", "")
	ifaceStr := findFs.StringP("iface", "i", "", "")
	timeout := findFs.StringP("timeout", "t", "", "")

	if len(opts) < 2 {
		findFs.Usage()
		return nil, 0, fmt.Errorf("no option given")
	}

	err := findFs.Parse(opts[1:])
	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return nil, 0, ErrHelp
		}
		findFs.Usage()
		return nil, 0, err
	}
	if len(findFs.Args()) > 0 {
		return nil, 0, fmt.Errorf("unexpected argument(s): %v", findFs.Args())
	}

	argValues := make(map[string]string, 3)
	if findFs.Changed("network") {
		argValues["network"] = *netStr
	}
	if findFs.Changed("host") {
		argValues["host"] = *hostStr
	}
	if findFs.Changed("iface") {
		argValues["iface"] = *ifaceStr
	}
	if findFs.Changed("timeout") {
		argValues["timeout"] = *timeout
	}

	return argValues, 0, nil
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
