// Package cmd is used for command line argument passing
package cmd

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	goversion "github.com/caarlos0/go-version"
	"github.com/spf13/cobra"
)

var (
	cfgFile          string
	sendNotification bool
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
	Version:      cleanVersion(buildVersion().GitVersion),
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
			version := buildVersion()
			version.GitVersion = cleanVersion(version.GitVersion)
			fmt.Println(version)
		},
	}
}

// buildVersion constructs and returns the application's version information.
func buildVersion() goversion.Info {
	return goversion.GetVersionInfo(
		goversion.WithAppDetails("gscn", "Network Scanning Utility.", ""),
	)
}

func cleanVersion(v string) string {
	// sometimes the version returned is of the form v0.2.4+dirty
	before, _, ok := strings.Cut(v, "+")
	if !ok {
		return v
	}
	return before
}
