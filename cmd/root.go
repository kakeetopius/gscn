// Package cmd is used for command line argument passing
package cmd

import (
	"fmt"
	"os"
	"os/user"
	"path"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gscn",
	Short: "A simple command line tool to carry out different operations on a network.",
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
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
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

		viper.SetConfigName("gscn")
		viper.SetConfigType("toml")
		viper.AddConfigPath(path.Join(home, ".config"))
		viper.AddConfigPath(".")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	err := viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}
	// fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())

	return nil
}
