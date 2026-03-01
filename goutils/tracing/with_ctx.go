package tracing

import "context"

// WithCtx is an interface that allows logging with a pre-defined context.
// This is useful for passing a context through a function chain without
// having to pass the context explicitly.
type WithCtx interface {
	Debug(msg string, fields Kvs)
	Info(msg string, fields Kvs)
	Warn(msg string, fields Kvs)
	Error(msg string, fields Kvs)
}

type withCtx struct {
	ctx context.Context
}

// Debug logs a debug message with the given key-value pairs.
func (w *withCtx) Debug(msg string, fields Kvs) {
	Debug(w.ctx, msg, fields)
}

// Info logs an info message with the given key-value pairs.
func (w *withCtx) Info(msg string, fields Kvs) {
	Info(w.ctx, msg, fields)
}

// Warn logs a warning message with the given key-value pairs.
func (w *withCtx) Warn(msg string, fields Kvs) {
	Warn(w.ctx, msg, fields)
}

// Error logs an error message with the given key-value pairs.
func (w *withCtx) Error(msg string, fields Kvs) {
	Error(w.ctx, msg, fields)
}

// WithContext returns a new WithCtx instance with the given context.
func WithContext(ctx context.Context) *withCtx {
	return &withCtx{
		ctx: ctx,
	}
}
