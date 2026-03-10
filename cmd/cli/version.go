package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "0.1.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of envsh",
	Run: func(cmd *cobra.Command, args []string) {
		_, _ = fmt.Printf("envsh %s\n", Version)
	},
}
