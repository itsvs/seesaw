package cmd

import (
	"github.com/itsvs/seesaw/goutils/errors"
	"github.com/itsvs/seesaw/goutils/tracing"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// the errors package is a collection of utilities for working with errors.
// it wraps the standard library's error type with additional functionality,
// specifically for creating constant errors as well as wrapping errors with
// an additional message.

var errorsCmd = &cobra.Command{
	Use:   "errors",
	Short: "Runs some examples of the errors package",
	Long:  `Runs some examples of the errors package.`,
}

var constantMsg string

var errorsConstantCmd = &cobra.Command{
	Use:   "constant",
	Short: "Creates an emits a constant error",
	Long:  `Creates an emits a constant error.`,
	Run: func(cmd *cobra.Command, args []string) {
		// create a constant error
		err := errors.Constant(constantMsg)

		// emit the error
		tracing.Error(cmd.Context(), err.Error(), tracing.Kvs{
			"error": err,
		})
	},
}

var wrappedMsg string

var errorsWrappedCmd = &cobra.Command{
	Use:   "wrapped",
	Short: "Wraps assert.AnError with a message",
	Long:  `Wraps assert.AnError with a message.`,
	Run: func(cmd *cobra.Command, args []string) {
		// wrap the error
		err := errors.Wrap(assert.AnError, wrappedMsg)

		// emit the error
		tracing.Error(cmd.Context(), err.Error(), tracing.Kvs{
			"error": err,
		})
	},
}

func init() {
	rootCmd.AddCommand(errorsCmd)
	errorsCmd.AddCommand(errorsConstantCmd)
	errorsConstantCmd.Flags().StringVarP(&constantMsg, "msg", "m", "This is a constant error", "The message to emit")
	errorsCmd.AddCommand(errorsWrappedCmd)
	errorsWrappedCmd.Flags().StringVarP(&wrappedMsg, "msg", "m", "This is a wrapped error", "The message to emit")
}
