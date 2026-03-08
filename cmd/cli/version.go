package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of envsh",
	Run: func(cmd *cobra.Command, args []string) {
		_, _ = fmt.Printf("envsh %s\n", Version)
	},
}
