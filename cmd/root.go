// Package cmd is used for command line argument passing
package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile   string
	notify    bool
	appConfig *viper.Viper
	debug     bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:          "gscn",
	Short:        "A simple command line tool to carry out different operations on a network.",
	SilenceUsage: true,
	// Runs after flags are passed but before RunE runs
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		err := initialiseConfig()
		if err != nil {
			return err
		}

		return nil
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
	rootCmd.PersistentFlags().BoolVar(&notify, "notify", false, "Send scan results via a configured notifier in $HOME/config/gscn.toml file")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Run in debug mode")

	rootCmd.AddCommand(
		DiscoverCmd(),
		ScanCmd(),
	)

	if runtime.GOOS == "linux" {
		rootCmd.AddCommand(WifiCmd())
	}
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
