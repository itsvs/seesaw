package policyengine

import (
	"context"
	"fmt"
)

// A Policy Engine is a rules engine that executes a set of steps in a specific
// order. An engine operates on a baggage, which contains inputs to the engine
// as well as any dependencies fetched by the steps themselves. The execution
// of an engine proceeds as follows:
//
//  1. The engine may be configured with a breaker function. If the breaker
//     function returns true, the engine will skip execution and return an error
//     with the given reason. This is useful for implementing things like rate
//     limiting or flag-gated features.
//  2. The engine will execute each step in order. For each step, we will:
//     - Check if the step is eligible to run.
//     - Prepare any dependencies for the step.
//     - Apply the step's policy.
//  3. The engine will return the first terminal output from any step. If no
//     terminal output is found, the engine will return an error (and the output
//     will be that of the last step run).
//
// A step can be thought of as a function that takes a baggage and returns an
// output. It has three components:
//
//  1. IsEligible: This function returns true if the step should run. If it
//     returns false, the step will not run and the engine will proceed to the
//     next step.
//  2. PrepareDependencies: This function is called before the step is applied.
//     It is responsible for fetching any dependencies for the step. It is the
//     only function that can write to the baggage and interact with anything
//     that requires a context. This is deliberate; it enforces that policies
//     themselves are pure functions that do not have side effects.
//  3. ApplyPolicy: This function is called to apply the step's policy. The
//     output of this function is returned to the engine.
//
// An implementation of this interface is provided and should cover most use
// cases. This interface is exposed so that it may be mocked for testing
// purposes or extended with additional functionality if desired.

// EngineBaggage is an interface that an engine's baggage must implement. The
// baggage is used to pass data between steps and the engine itself.
type EngineBaggage interface {
	// GetLogFields returns a map of key-value pairs that will be added to any
	// logs emitted by the engine during or after execution.
	GetLogFields() map[string]any
}

// BreakerFn is a function that returns true if the engine should skip executing
// steps. If it returns true, the engine will skip execution and return an error
// with the given reason. This is useful for implementing things like rate
// limiting or flag-gated features. The reason is represented as an error so
// that it can be wrapped with additional context if desired.
type BreakerFn[B EngineBaggage] func(baggage B) (tripped bool, reason error)

// StepOutput is an interface that a step's (and therefore engine's) output
// must implement. For now, the two requirements are that the output must be
// able to be converted to a string and that it must be able to indicate if it
// is terminal (i.e. if the engine should stop executing steps).
type StepOutput interface {
	fmt.Stringer
	// IsTerminal returns true if the output is terminal. If it is, the engine
	// will stop executing steps and return this output.
	IsTerminal() bool
}

// EngineOutput is the output of an engine. It contains the steps that were
// executed and the output of the last step. In the future, this may be extended
// to include other metadata if desired.
type EngineOutput[B EngineBaggage, O StepOutput] struct {
	StepsRun []string
	Output   O
}

// Step is an interface that a step must implement.
type Step[B EngineBaggage, O StepOutput] interface {
	// GetName returns the name of the step.
	GetName() string
	// IsEligible returns true if the step should run. If it returns false, the
	// step will not run and the engine will proceed to the next step.
	IsEligible(baggage B) (eligible bool, reason string)
	// PrepareDependencies is called before the step is applied. It is
	// responsible for fetching any dependencies for the step. It is the only
	// function that can write to the baggage and interact with anything that
	// requires a context. This is deliberate; it enforces that policies
	// themselves are pure functions that do not have side effects.
	PrepareDependencies(ctx context.Context, baggage *B) error
	// ApplyPolicy is called to apply the step's policy. The output of this
	// function is returned to the engine.
	ApplyPolicy(baggage B) O
}

// Engine is an interface that an engine must implement.
type Engine[Baggage EngineBaggage, Output StepOutput] interface {
	// IsBreakerTripped returns true if the engine should skip executing steps.
	// If it returns true, the engine will skip execution and return an error with
	// the given reason. This is useful for implementing things like rate limiting
	// or flag-gated features. The reason is represented as an error so that it
	// can be wrapped with additional context if desired.
	IsBreakerTripped(baggage Baggage) (tripped bool, reason error)
	// Run executes the engine. If the engine doesn't have a breaker, this is
	// equivalent to calling RunBypassBreaker.
	Run(ctx context.Context, baggage *Baggage) (output EngineOutput[Baggage, Output], err error)
	// RunBypassBreaker executes the engine without checking the breaker. This
	// is useful for testing the engine without a breaker.
	RunBypassBreaker(ctx context.Context, baggage *Baggage) (output EngineOutput[Baggage, Output], err error)
}
