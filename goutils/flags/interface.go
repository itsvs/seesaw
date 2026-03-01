package flags

import "testing"

type Interface interface {
	GetBool(flagName string, defaultValue bool) bool
	GetString(flagName string, defaultValue string) string
	GetFloat(flagName string, defaultValue float64) float64
}

type InterfaceForTesting interface {
	Interface
	SetBoolForTest(t *testing.T, flagName string, defaultValue bool)
	SetStringForTest(t *testing.T, flagName string, defaultValue string)
	SetFloatForTest(t *testing.T, flagName string, defaultValue float64)
}
