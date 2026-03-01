package optional

// Bool is an optional boolean value. It store a pointer to a bool
// in order to distinguish between `false` and `unset`.
type Bool struct {
	value *bool
}

// NewBool creates a new Bool with the given value.
func NewBool(value bool) Bool {
	return Bool{&value}
}

// IsSet returns true if the Bool has been set.
func (b Bool) IsSet() bool {
	return b.value != nil
}

// Get returns the value of the Bool if it exists. Otherwise, it
// returns an ErrOptionalNotSet.
func (b Bool) Get() (bool, error) {
	if b.value == nil {
		return false, ErrOptionalNotSet
	}
	return *b.value, nil
}

// MustGet returns the value of the Bool if it exists. Otherwise,
// it panics with ErrOptionalNotSet.
func (b Bool) MustGet() bool {
	if b.value == nil {
		panic(ErrOptionalNotSet)
	}
	return *b.value
}
