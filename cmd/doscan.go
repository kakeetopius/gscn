package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"

	"github.com/kakeetopius/gscn/internal/config"
	"github.com/kakeetopius/gscn/internal/notify"
	"github.com/kakeetopius/gscn/scanner"
	"golang.org/x/term"
)

func DoScan(ctx context.Context, scanner scanner.Scanner, config *config.Config) error {
	if config == nil {
		return fmt.Errorf("config not initialised.")
	}

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	results, err := scanner.Scan(ctx)
	if err != nil {
		return err
	}

	out := os.Stdout
	var output []byte

	if config.ResultsOutputFile != "" {
		f, openErr := os.OpenFile(config.ResultsOutputFile, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o750)
		if openErr != nil {
			return openErr
		}
		defer f.Close()
		out = f
	}

	if config.JSONResults {
		jsonBytes, jsonErr := getJSONResults(results, config.JSONPretty)
		if jsonErr != nil {
			return jsonErr
		}
		output = jsonBytes
	} else {
		output = []byte(results.String())
	}

	if isTTY(out) && !config.JSONResults {
		results.Print()
	} else {
		_, err = out.Write(output)
		if err != nil {
			return err
		}
	}

	if config.Notify && ctx.Err() == nil { // only send results if we haven't been cancelled
		return notify.
			NewDispatcher(buildNotifiers(config)...).
			Dispatch(ctx, results)
	}

	return nil
}

// isTTY checks if the provided file is a terminal. It returns true if the file is a terminal, otherwise false.
func isTTY(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// getJSONResults marshals the scan results into JSON format. If jsonPretty is true, it returns a pretty-printed JSON otherwise, it returns compact JSON.
func getJSONResults(r scanner.ScanResults, jsonPretty bool) ([]byte, error) {
	if jsonPretty {
		return json.MarshalIndent(r, "", "  ")
	} else {
		return json.Marshal(r)
	}
}

func buildNotifiers(c *config.Config) []notify.Notifier {
	var ns []notify.Notifier

	if c.Notifiers.Email.Enabled {
		e := c.Notifiers.Email
		ns = append(ns, notify.EmailNotifier{
			SendAddress: e.SendAddress,
			RcptAddress: e.RecptAddress,
			UserName:    e.UserName,
			Password:    e.Password,
		})
	}

	if c.Notifiers.Discord.Enabled {
		d := c.Notifiers.Discord
		ns = append(ns, notify.DiscordNotifier{
			Token:       d.Token,
			ChannelID:   d.ChannelID,
			ChannelName: d.ChannelName,
		})
	}

	return ns
}
