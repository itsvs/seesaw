package cmd

import (
	"context"

	"github.com/itsvs/seesaw/goutils/tracing"
	"github.com/spf13/cobra"
)

var tracingCmd = &cobra.Command{
	Use:   "tracing",
	Short: "Emits logs of various levels to demonstrate the tracing package",
	Long:  `Emits logs of various levels to demonstrate the tracing package.`,
}

var tracingMsg string

var tracingInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Emits an info log",
	Long:  `Emits an info log.`,
	Run: func(cmd *cobra.Command, args []string) {
		tracing.Info(context.Background(), tracingMsg, tracing.Kvs{})
	},
}

var tracingDebugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Emits a debug log",
	Long:  `Emits a debug log.`,
	Run: func(cmd *cobra.Command, args []string) {
		tracing.Debug(context.Background(), tracingMsg, tracing.Kvs{})
	},
}

var tracingWarnCmd = &cobra.Command{
	Use:   "warn",
	Short: "Emits a warn log",
	Long:  `Emits a warn log.`,
	Run: func(cmd *cobra.Command, args []string) {
		tracing.Warn(context.Background(), tracingMsg, tracing.Kvs{})
	},
}

var tracingErrorCmd = &cobra.Command{
	Use:   "error",
	Short: "Emits an error log",
	Long:  `Emits an error log.`,
	Run: func(cmd *cobra.Command, args []string) {
		tracing.Error(context.Background(), tracingMsg, tracing.Kvs{})
	},
}

func init() {
	rootCmd.AddCommand(tracingCmd)
	tracingCmd.AddCommand(tracingInfoCmd)
	tracingCmd.AddCommand(tracingDebugCmd)
	tracingCmd.AddCommand(tracingWarnCmd)
	tracingCmd.AddCommand(tracingErrorCmd)
	tracingCmd.Flags().StringVarP(&tracingMsg, "msg", "m", "This is a test message", "The message to emit")
}
