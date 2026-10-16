// Package cmd is used for command line argument passing
package cmd

import (
	"fmt"
	"runtime"
	"strings"

	goversion "github.com/caarlos0/go-version"
	"github.com/kakeetopius/gscn/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// rootCmd represents the base command when called without any subcommands

func Command() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "gscn",
		Short:        "A simple command line tool to carry out different operations on a network.",
		SilenceUsage: true,
		Version:      cleanVersion(buildVersion().GitVersion),
	}
	rootCmd.Flags().SortFlags = false
	rootCmd.PersistentFlags().SortFlags = false

	rootCmd.PersistentFlags().String("config", "", "config file (default is $HOME/.config/gscn.toml)")
	rootCmd.PersistentFlags().Bool("debug", false, "Run in debug mode")
	rootCmd.PersistentFlags().StringP("out", "o", "", "Save scan results to an output file")
	rootCmd.PersistentFlags().BoolP("json", "j", false, "Print scan results in json format.")
	rootCmd.PersistentFlags().BoolP("pretty", "P", false, "Print scan results in pretty json format.")
	rootCmd.PersistentFlags().Bool("notify", false, "Send scan results via a configured notifier in $HOME/config/gscn.toml file")

	rootCmd.MarkFlagFilename("out")

	rootCmd.AddCommand(
		DiscoverCmd(),
		ScanCmd(),
		versionCmd(),
	)

	if runtime.GOOS == "linux" {
		rootCmd.AddCommand(WifiCmd())
	}

	return rootCmd
}

// rootCmdConfigSetup returns a function that binds some of the global flags to the configuration.
func rootCmdConfigSetup(cmd *cobra.Command) config.ConfigSetupFunc {
	return func(v *viper.Viper) {
		err := v.BindPFlag("debug", cmd.Flags().Lookup("debug"))
		cobra.CheckErr(err)
		err = v.BindPFlag("out", cmd.Flags().Lookup("out"))
		cobra.CheckErr(err)
		err = v.BindPFlag("json", cmd.Flags().Lookup("json"))
		cobra.CheckErr(err)
		err = v.BindPFlag("pretty", cmd.Flags().Lookup("pretty"))
		cobra.CheckErr(err)
		err = v.BindPFlag("notify", cmd.Flags().Lookup("notify"))
		cobra.CheckErr(err)
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

func configPath(cmd *cobra.Command) string {
	config, _ := cmd.Flags().GetString("config")
	return config
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
