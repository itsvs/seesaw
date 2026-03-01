package errors

import "maps"

// kvs add useful information to errors in the form of key-value pairs.

type kv struct {
	key   string
	value any
}

type kvError struct {
	kvs map[string]any
	err error
}

// Error returns the string representation of the error.
func (e *kvError) Error() string {
	return e.err.Error()
}

// Kvs returns a map from string keys to any (generally primitive) values
// associated with an error. It includes any Kvs from wrapped errors, but
// parent error keys take precedence.
func (e *kvError) Kvs() map[string]any {
	kvs := make(map[string]any)
	maps.Copy(kvs, e.kvs)

	// if there is a wrapped kvError, add all of its Kvs to the
	// map we're about to return. skip any keys that have already
	// been set by the parent error itself, as those take priority.
	for k, v := range Kvs(e.err) {
		if _, ok := kvs[k]; !ok {
			kvs[k] = v
		}
	}

	return kvs
}

// Kvs returns a map from string keys to any (generally primitive) values
// associated with an error. It includes any Kvs from wrapped errors, but
// parent error keys take precedence.
func Kvs(err error) map[string]any {
	if ekv, ok := err.(*kvError); ok {
		return ekv.Kvs()
	}
	if wrapped, ok := err.(wrapError); ok {
		return wrapped.err.(*kvError).Kvs()
	}
	return nil
}

// newWithKvs returns an error that may have Kvs associated with it. This is not
// meant to be used directly outside of this package. To instantiate an error
// with Kvs, use errors.New or errors.Wrap. Constant errors cannot have Kvs.
func newWithKvs(err error, kvs ...kv) *kvError {
	kvMap := make(map[string]any)
	for _, kv := range kvs {
		kvMap[kv.key] = kv.value
	}

	return &kvError{
		kvs: kvMap,
		err: err,
	}
}

// Kv converts a key-value pair to the errors package's internal representation
// of an error kv. The representative struct is private, as it is not meant to
// be used directly outside of this package.
func Kv(key string, value any) kv {
	return kv{key, value}
}
