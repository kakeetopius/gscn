package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/kakeetopius/gscn/internal/argparser"
)

func main() {
	if len(os.Args) < 2 {
		argparser.GeneralUsage()
		return
	}

	cmd, err := argparser.ParseArgs(os.Args[1:])
	if err != nil {
		if errors.Is(err, argparser.ErrHelp) {
			return
		}
		fmt.Println("Error:", err)
		return
	}

	cmd.Run()
}
