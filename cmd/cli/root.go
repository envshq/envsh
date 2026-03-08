package main

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile   string
	outputFmt string // "table", "json", "plain"
	serverURL string
)

// rootCmd is the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "envsh",
	Short: "Zero-knowledge secret sync for development teams",
	Long: `envsh — the only secrets manager that can't read your secrets.

All encryption happens on your machine using your SSH keys.
The server stores only ciphertext and cannot decrypt your secrets.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		PrintError(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ~/.envsh/config.json)")
	rootCmd.PersistentFlags().StringVar(&outputFmt, "output", "table", "output format: table, json, plain")
	rootCmd.PersistentFlags().StringVar(&serverURL, "server", "", "envsh server URL (overrides config)")

	// Register subcommands
	rootCmd.AddCommand(versionCmd)
}
