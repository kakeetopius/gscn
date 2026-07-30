package scanner

import (
	"encoding/json"
	"os"

	"github.com/kakeetopius/gscn/internal/notify"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

type ScanOptions struct {
	ResultsOutputFile string
	PrintJSON         bool
	PrintJSONPretty   bool
	Notify            bool
	Config            *viper.Viper
}

func DoScan(scanner Scanner, opts ScanOptions) error {
	results, err := scanner.Scan()
	if err != nil {
		return err
	}

	out := os.Stdout
	var output []byte

	if opts.ResultsOutputFile != "" {
		f, openErr := os.OpenFile(opts.ResultsOutputFile, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o754)
		if openErr != nil {
			return openErr
		}
		defer f.Close()
		out = f
	}

	var printDefault bool // means no json output or any future output formats

	if opts.PrintJSON {
		jsonBytes, jsonErr := getJSONResults(results, opts.PrintJSONPretty)
		if jsonErr != nil {
			return jsonErr
		}
		output = jsonBytes
	} else {
		output = []byte(results.String())
		printDefault = true
	}

	if isTTY(out) && printDefault {
		results.Print()
	} else {
		_, err = out.Write(output)
		if err != nil {
			return err
		}
	}

	if opts.Notify {
		notifer, err := notify.NotifierFromConfig(opts.Config)
		if err != nil {
			return err
		}
		notify.SendMessageWithNotifier(results, notifer)
	}

	return nil
}

// isTTY checks if the provided file is a terminal. It returns true if the file is a terminal, otherwise false.
func isTTY(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// getJSONResults marshals the scan results into JSON format. If jsonPretty is true, it returns a pretty-printed JSON otherwise, it returns compact JSON.
func getJSONResults(r ScanResults, jsonPretty bool) ([]byte, error) {
	if jsonPretty {
		return json.MarshalIndent(r, "", "  ")
	} else {
		return json.Marshal(r)
	}
}
