package optional

// String is an optional string value. It store a pointer to a string
// in order to distinguish between `""` and `unset`.
type String struct {
	value *string
}

// NewString creates a new String with the given value.
func NewString(value string) String {
	return String{&value}
}

// IsSet returns true if the String has been set.
func (s String) IsSet() bool {
	return s.value != nil
}

// Get returns the value of the String if it exists. Otherwise, it
// returns an ErrOptionalNotSet.
func (s String) Get() (string, error) {
	if s.value == nil {
		return "", ErrOptionalNotSet
	}
	return *s.value, nil
}

// MustGet returns the value of the String if it exists. Otherwise,
// it panics with ErrOptionalNotSet.
func (s String) MustGet() string {
	if s.value == nil {
		panic(ErrOptionalNotSet)
	}
	return *s.value
}
