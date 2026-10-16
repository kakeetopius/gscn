package main

import (
	"os"

	"github.com/kakeetopius/gscn/cmd"
)

func main() {
	err := cmd.Command().Execute()
	if err != nil {
		os.Exit(1)
	}
}
