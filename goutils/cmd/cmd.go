package cmd

import (
	"context"
	"os"

	"github.com/itsvs/seesaw/goutils/tracing"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "goutils",
	Short: "goutils is a collection of utilities for Golang",
	Long: `goutils is a collection of utilities for Golang. This is a CLI tool for
interacting with the utilities via various sample programs.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		tracing.Error(context.Background(), "error executing root command", tracing.Kvs{
			"error": err,
		})
		os.Exit(1)
	}
}
