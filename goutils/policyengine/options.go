package policyengine

// EngineOption is an interface that policy engine options must implement.
// This is mostly just a generic interface to allow us to use type inference
// to add options to an engine.
type EngineOption interface {
	isEngineOption()
}

// engineName is an option that sets the name of the engine.
type engineName string

func (e engineName) isEngineOption() {}

// WithName sets the name of the engine.
func WithName(name string) EngineOption {
	return engineName(name)
}

// engineBreaker is an option that sets the breaker function for the engine.
type engineBreaker[B EngineBaggage] BreakerFn[B]

func (e engineBreaker[B]) isEngineOption() {}

// WithBreaker sets the breaker function for the engine.
func WithBreaker[B EngineBaggage](breaker BreakerFn[B]) EngineOption {
	return engineBreaker[B](breaker)
}
