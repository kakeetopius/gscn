// Package cmd is used for command line argument passing
package cmd

import (
	"fmt"
	"os"
	"os/user"
	"path"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	notify  bool
	config  *viper.Viper
	debug   bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:          "gscn",
	Short:        "A simple command line tool to carry out different operations on a network.",
	SilenceUsage: true,
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
	rootCmd.PersistentFlags().BoolVar(&notify, "notify", false, "Send scan results via a configured notifier in $HOME/config/gscn.toml file")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Run in debug mode.")

	rootCmd.AddCommand(
		DiscoverCmd(),
		ScanCmd(),
		WifiCmd(),
	)
}

// initialiseConfig initializes and reads the application configuration from a TOML file.
// It handles both root and non-root user scenarios by determining the appropriate
// home directory. The function looks for a "gscn.toml" config file in ~/.config
// or the current directory.
// Returns a configured Viper instance or an error if setup fails.
func initialiseConfig() error {
	config = viper.New()
	if cfgFile != "" {
		// Use config file from the flag.
		config.SetConfigFile(cfgFile)
	} else {
		home := ""
		if os.Geteuid() == 0 {
			// running as root
			sudoUser := os.Getenv("SUDO_USER")
			if sudoUser == "" {
				return fmt.Errorf("could not get sudo user variable")
			}
			u, err := user.Lookup(sudoUser)
			if err != nil {
				return err
			}
			home = u.HomeDir
		} else {
			h, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			home = h
		}

		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		config.SetConfigName("gscn")
		config.SetConfigType("toml")
		config.AddConfigPath(path.Join(home, ".config"))
		config.AddConfigPath(cwd)
	}

	config.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	err := config.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
		// No need to return error if config file not found
		return nil
	}
	if debug {
		info := pterm.Info.Sprintln("Using config file:", config.ConfigFileUsed())
		fmt.Fprintln(os.Stderr, info)
	}

	return nil
}
