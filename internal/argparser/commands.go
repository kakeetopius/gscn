package argparser

import (
	"fmt"
	"strings"

	"github.com/kakeetopius/gscn/internal/net/discover"
	"github.com/kakeetopius/gscn/internal/net/scan"
)

type Runner func(map[string]string, int) error

type Command struct {
	Name      string
	Arguments map[string]string
	Flags     int
	argParser func([]string) (map[string]string, int, error)
	cmdRun    Runner
}

var commands = []Command{
	{Name: "discover", argParser: discoverArgParser, cmdRun: discover.RunDiscover},
	{Name: "scan", argParser: scanArgParser, cmdRun: scan.RunScan},
}

func (c *Command) Run() {
	c.cmdRun(c.Arguments, c.Flags)
}

func (c *Command) addArgs(args map[string]string, flags int) {
	c.Arguments = args
	c.Flags = flags
}

func getCommand(commandName string) (*Command, error) {
	for _, command := range commands {
		if strings.HasPrefix(command.Name, commandName) {
			return &command, nil
		}
	}

	return nil, fmt.Errorf("unknown command: %v", commandName)
}
