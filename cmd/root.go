// Package cmd is used for command line argument passing
package cmd

import (
	"fmt"
	"os"
	"runtime"

	goversion "github.com/caarlos0/go-version"
	"github.com/kakeetopius/gscn/internal/notify"
	"github.com/kakeetopius/gscn/pkg/scanner"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile          string
	sendNotification bool
	appConfig        *viper.Viper
	debug            bool
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
	rootCmd.PersistentFlags().BoolVar(&sendNotification, "notify", false, "Send scan results via a configured notifier in $HOME/config/gscn.toml file")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Run in debug mode")

	rootCmd.AddCommand(
		DiscoverCmd(),
		ScanCmd(),
		versionCmd(),
	)

	if runtime.GOOS == "linux" {
		rootCmd.AddCommand(WifiCmd())
	}
}

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
	scanner.PrintResults()
	if sendNotification {
		return scanner.SendResultsViaNotifier()
	}

	return nil
}

func getNotifier() (notify.Notifier, error) {
	notifierName := appConfig.GetString("notifier.type")
	if notifierName == "" {
		return nil, fmt.Errorf("no notifier type set in the config file")
	}
	return notify.NotifierByName(notifierName, appConfig)
}
