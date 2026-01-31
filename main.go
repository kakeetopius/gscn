package main

import (
	"context"
	"fmt"
	"os"

	"github.com/kakeetopius/gscn/internal/argparser"
)

func main() {
	cmd := argparser.GetCommand()

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
