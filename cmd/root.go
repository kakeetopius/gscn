// Package cmd is used for command line argument passing
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	goversion "github.com/caarlos0/go-version"
	"github.com/kakeetopius/gscn/internal/notify"
	"github.com/kakeetopius/gscn/scanner"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

var (
	cfgFile          string
	sendNotification bool
	appConfig        *viper.Viper
	debug            bool
	outputFile       string
	outputJSON       bool
	jsonPretty       bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:          "gscn",
	Short:        "A simple command line tool to carry out different operations on a network.",
	SilenceUsage: true,
	Version:      buildVersion().GitVersion,
	// Runs after flags are passed but before RunE runs
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initialiseConfig()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().SortFlags = false
	rootCmd.PersistentFlags().SortFlags = false

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/gscn.toml)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Run in debug mode")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "out", "o", "", "Save scan results to an output file")
	rootCmd.PersistentFlags().BoolVarP(&outputJSON, "json", "j", false, "Print scan results in json format.")
	rootCmd.PersistentFlags().BoolVarP(&jsonPretty, "pretty", "P", false, "Print scan results in pretty json format.")
	rootCmd.PersistentFlags().BoolVar(&sendNotification, "notify", false, "Send scan results via a configured notifier in $HOME/config/gscn.toml file")

	rootCmd.MarkFlagFilename("out")
	rootCmd.AddCommand(
		DiscoverCmd(),
		ScanCmd(),
		versionCmd(),
	)

	if runtime.GOOS == "linux" {
		rootCmd.AddCommand(WifiCmd())
	}
}

// versionCmd returns a cobra command that displays the application's version information.
func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "version",
		Short:   "Show detailed version information",
		Aliases: []string{"v"},
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(buildVersion().String())
		},
	}
}

// buildVersion constructs and returns the application's version information.
func buildVersion() goversion.Info {
	return goversion.GetVersionInfo(
		goversion.WithAppDetails("gscn", "Network Scanning Utility.", ""),
	)
}

// initialiseConfig creates and loads the application configuration.
// It prefers an explicit config file when provided, otherwise it resolves the
// default config directory, enables environment variable overrides, and loads
// the resulting configuration if present.
func initialiseConfig() error {
	appConfig = viper.New()
	if cfgFile != "" {
		// Use config file from the flag.
		appConfig.SetConfigFile(cfgFile)
	} else {
		configDir, err := ConfigDir()
		if err != nil {
			return err
		}
		appConfig.SetConfigName("gscn")
		appConfig.AddConfigPath(configDir)
	}

	appConfig.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	err := appConfig.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
		// No need to return error if config file not found
		return nil
	}
	if debug {
		info := pterm.Info.Sprintln("Using config file:", appConfig.ConfigFileUsed())
		fmt.Fprintln(os.Stderr, info)
	}

	return nil
}

// doScan starts the scanning process using the provided scanner. If notifications are enabled, it initializes a notifier, attaches it to the scanner,
// and sends the scan results upon completion. It also prints the findings to standard output or to an output file depending on the command line options given.
func doScan(scanner scanner.Scanner) error {
	if sendNotification {
		notifier, err := getNotifier()
		if err != nil {
			return err
		}
		scanner.SetNotifier(notifier)
	}

	err := scanner.Scan()
	if err != nil {
		return err
	}

	out := os.Stdout
	var output []byte

	if outputFile != "" {
		f, openErr := os.OpenFile(outputFile, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o754)
		if openErr != nil {
			return openErr
		}
		defer f.Close()
		out = f
	}

	var printDefault bool // no json output or any future output formats

	if outputJSON {
		jsonBytes, jsonErr := getJSONResults(scanner.Results())
		if jsonErr != nil {
			return jsonErr
		}
		output = jsonBytes
	} else {
		output = []byte(scanner.Results().String())
		printDefault = true
	}

	if isTTY(out) && printDefault {
		scanner.PrintResults()
	} else {
		_, err = out.Write(output)
		if err != nil {
			return err
		}
	}

	if sendNotification {
		return scanner.SendResultsViaNotifier()
	}

	return nil
}

// getJSONResults marshals the scan results into JSON format. If jsonPretty is true, it returns a pretty-printed JSON otherwise, it returns compact JSON.
func getJSONResults(r scanner.ScanResults) ([]byte, error) {
	if jsonPretty {
		return json.MarshalIndent(r, "", "  ")
	} else {
		return json.Marshal(r)
	}
}

// getNotifier retrieves the notifier based on the configuration.
// It returns an error if no notifier type is set in the config file or if the notifier cannot be initialized.
func getNotifier() (notify.Notifier, error) {
	notifierName := appConfig.GetString("notifier.type")
	if notifierName == "" {
		return nil, fmt.Errorf("no notifier type set in the config file")
	}
	return notify.NotifierByName(notifierName, appConfig)
}

// isTTY checks if the provided file is a terminal. It returns true if the file is a terminal, otherwise false.
func isTTY(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
