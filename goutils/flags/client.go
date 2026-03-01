package flags

type client struct {
	values map[string]any
}

func (c *client) GetBool(flagName string, defaultValue bool) bool {
	if val, ok := c.values[flagName]; ok {
		if valBool, ok := val.(bool); ok {
			return valBool
		}
	}
	return defaultValue
}

func (c *client) GetString(flagName string, defaultValue string) string {
	if val, ok := c.values[flagName]; ok {
		if valStr, ok := val.(string); ok {
			return valStr
		}
	}
	return defaultValue
}

func (c *client) GetFloat(flagName string, defaultValue float64) float64 {
	if val, ok := c.values[flagName]; ok {
		if valFloat, ok := val.(float64); ok {
			return valFloat
		}
	}
	return defaultValue
}

func New(flagValues map[string]any) Interface {
	return &client{
		values: flagValues,
	}
}
