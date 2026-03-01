package errors

import "strings"

// Constant is a type alias for a string that implements the error interface.
// It is used to create constant error messages.
type Constant string

// Error returns the string representation of the error.
func (err Constant) Error() string {
	return string(err)
}

// Is checks if the error is equal to or a prefix of the target error.
func (err Constant) Is(target error) bool {
	tgt, msg := target.Error(), err.Error()
	return tgt == msg || strings.HasPrefix(tgt, msg+": ")
}
