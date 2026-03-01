package flags

import "testing"

type clientForTesting struct {
	baseClient *client
}

func (c *clientForTesting) GetBool(flagName string, defaultValue bool) bool {
	return c.baseClient.GetBool(flagName, defaultValue)
}

func (c *clientForTesting) GetString(flagName string, defaultValue string) string {
	return c.baseClient.GetString(flagName, defaultValue)
}

func (c *clientForTesting) GetFloat(flagName string, defaultValue float64) float64 {
	return c.baseClient.GetFloat(flagName, defaultValue)
}

func (c *clientForTesting) SetBoolForTest(t *testing.T, flagName string, defaultValue bool) {
	currValue := c.baseClient.GetBool(flagName, defaultValue)
	t.Cleanup(func() {
		c.baseClient.values[flagName] = currValue
	})
	c.baseClient.values[flagName] = defaultValue
}

func (c *clientForTesting) SetStringForTest(t *testing.T, flagName string, defaultValue string) {
	currValue := c.baseClient.GetString(flagName, defaultValue)
	t.Cleanup(func() {
		c.baseClient.values[flagName] = currValue
	})
	c.baseClient.values[flagName] = defaultValue
}

func (c *clientForTesting) SetFloatForTest(t *testing.T, flagName string, defaultValue float64) {
	currValue := c.baseClient.GetFloat(flagName, defaultValue)
	t.Cleanup(func() {
		c.baseClient.values[flagName] = currValue
	})
	c.baseClient.values[flagName] = defaultValue
}

func NewForTesting(flagValues map[string]any) InterfaceForTesting {
	bc, _ := New(flagValues).(*client)
	return &clientForTesting{
		baseClient: bc,
	}
}
