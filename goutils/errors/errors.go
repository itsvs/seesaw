package errors

import "errors"

// errors is a package that provides a set of functions for working with errors.
// It is a wrapper around the errors package that provides additional functionality.
// It is used to create and manipulate errors in a more convenient way.

// New creates a new error with the given message.
func New(msg string, kvs ...kv) error {
	return newWithKvs(errors.New(msg), kvs...)
}

// Unwrap returns the wrapped error.
func Unwrap(err error) error {
	return errors.Unwrap(err)
}

// As checks if the error is an instance of the target type.
func As(err error, target any) bool {
	return errors.As(err, target)
}

// Is checks if the error is equal to or a prefix of the target error.
func Is(err error, target error) bool {
	return errors.Is(err, target)
}
