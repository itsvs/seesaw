package tracing

import (
	"context"
	"os"

	"log/slog"
)

// tracing is a package that provides a set of functions for logging messages with context.
// It is a wrapper around the slog package that provides additional functionality.
// It is used to create and manipulate logs in a more convenient way.

// Kvs is an alias for a map of string keys to any values.
// It is used to pass key-value pairs to the logging functions.
type Kvs map[string]any

func (k Kvs) args() []any {
	var args []any
	for k, v := range map[string]any(k) {
		args = append(args, k, v)
	}
	return args
}

// logger is a global slog.Logger instance.
var logger *slog.Logger

func init() {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
}

// Debug logs a debug message with the given key-value pairs.
func Debug(ctx context.Context, msg string, fields Kvs) {
	logger.DebugContext(ctx, msg, fields.args()...)
}

// Info logs an info message with the given key-value pairs.
func Info(ctx context.Context, msg string, fields Kvs) {
	logger.InfoContext(ctx, msg, fields.args()...)
}

// Warn logs a warning message with the given key-value pairs.
func Warn(ctx context.Context, msg string, fields Kvs) {
	logger.WarnContext(ctx, msg, fields.args()...)
}

// Error logs an error message with the given key-value pairs.
func Error(ctx context.Context, msg string, fields Kvs) {
	logger.ErrorContext(ctx, msg, fields.args()...)
}
