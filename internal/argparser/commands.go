package argparser

import (
	"github.com/kakeetopius/gscn/internal/net/find"
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

var commands = map[string]Command{
	"find": {Name: "find", argParser: findArgParser, cmdRun: find.RunFind},
	"scan": {Name: "scan", argParser: scanArgParser, cmdRun: scan.RunScan},
}

func (c *Command) Run() {
	c.cmdRun(c.Arguments, c.Flags)
}

func (c *Command) addArgs(args map[string]string, flags int) {
	c.Arguments = args
	c.Flags = flags
}
