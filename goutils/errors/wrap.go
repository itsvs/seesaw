package errors

import "fmt"

// wrapError is a wrapper around an error that adds a message to the error.
// It implements the error interface and the Unwrap method.
type wrapError struct {
	err error
	msg string
}

// Error returns the string representation of the error.
func (err wrapError) Error() string {
	if err.err != nil {
		return fmt.Sprintf("%s: %v", err.msg, err.err)
	}
	return err.msg
}

// Unwrap returns the wrapped error.
func (err wrapError) Unwrap() error {
	return err.err
}

// Is checks if the error is equal to or a prefix of the target error.
func (err wrapError) Is(target error) bool {
	return Constant(err.msg).Is(target)
}

// Wrap wraps an error with a message.
func Wrap(err error, msg string, kvs ...kv) error {
	return wrapError{
		err: newWithKvs(err, kvs...),
		msg: msg,
	}
}
