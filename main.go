package main

import (
	"os"
	"fmt"
	"errors"

	"github.com/kakeetopius/gohunter/internal/flags"
)

func main() {
	if (len(os.Args) < 2) {
		flags.GeneralUsage()
		return
	}

	cmd, err := flags.ParseArgs(os.Args[1:])
	if (err != nil) {
		if (errors.Is(err, flags.ErrHelp)) {
			return
		}
		fmt.Println("Error:", err)
		return
	}

	cmd.Run()
}
