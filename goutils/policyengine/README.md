# Policy Engine

A library for applying atomic policies to input data to generate output. Policy
engines execute a series of steps, with support for conditional execution,
dependency preparation, and circuit breakers.

## Core Concepts

### Engine
The engine is the main orchestrator that executes steps sequentially. It
operates on a "baggage" object that contains input data and any dependencies
fetched during execution.

My implementation of the engine applies steps in the specified order, and I
present this as an invariant. However, I would encourage implementing steps such
that they aren't dependent on this. Most importantly, make sure that your steps
don't rely on _each other_, e.g. by assuming that a certain dependency will have
already been fetched.

In order to truly ensure that order doesn't matter, each step should fetch all
the dependencies it needs (consider making your dependency fetchers check that
a dependency hasn't been fetched already). Also, steps should really only return
a terminal output if they are actually able to make that determination on their
own. The example I present here has a "formal approval" step that returns a
terminal output under the assumption that it is the last step -- this should not
exist in an unordered engine. The way to establish formal approval properly
would be to let the engine terminate without an output, and to declare that this
semantically means that the transaction is approved:

```go
approved := false
if output.Output.IsTerminal() {
    // use the terminal output from the engine
    approved = output.Output.Approved
} else {
    approved = NonTerminalApprovalStatus
}
```

### Baggage
The baggage is a container that holds:
- Input data for the engine
- Dependencies fetched by steps
- Metadata for logging and tracing

The recommended way to distinguish between inputs and dependencies is using Go's
built-in public vs. private distinctions, i.e. make your input fields public and
make your dependencies private.

### Steps
A step represents a single policy or rule that can be applied to the baggage.
Each step has three components:

1. **IsEligible**: Determines if the step should run based on the current baggage state (pure function with no side effects)
2. **PrepareDependencies**: Fetches any required data and modifies the baggage (the only place side effects are allowed)
3. **ApplyPolicy**: Applies the actual policy logic (pure function with no side effects)

The policy engine enforces separation of concerns by establishing that only the
`PrepareDependencies` function can perform side effects, while other functions
remain pure. This design makes the system more predictable, testable, and easier
to debug.

### Output
Steps return output that can be either:
- **Terminal**: Stops engine execution and returns this output
- **Non-terminal**: Allows execution to continue to the next step

### Circuit Breaker
An optional breaker function that can halt engine execution before any steps
run. Useful for implementing rate limits, feature flags, or time-based cutoffs.

## Basic Usage

```go
// Define your baggage type
type MyBaggage struct {
    UserID string
    Amount float64
}

func (b MyBaggage) GetLogFields() map[string]any {
    return map[string]any{
        "user_id": b.UserID,
        "amount":  b.Amount,
    }
}

// Define your output type
type MyOutput struct {
    Approved bool
    Reason   string
}

func (o MyOutput) String() string {
    if o.Approved {
        return fmt.Sprintf("Approved: %s", o.Reason)
    }
    return fmt.Sprintf("Denied: %s", o.Reason)
}

func (o MyOutput) IsTerminal() bool {
    return reason != "" // If a reason has been set, then we have a verdict
}

// Create steps
steps := []engine.Step[MyBaggage, MyOutput]{
    &myValidationStep{},
    &myApprovalStep{},
}

// Create and run engine
policyEngine := engine.New(
    steps,
    engine.WithName("my-policy-engine"),
    engine.WithBreaker(func(baggage MyBaggage) (bool, error) {
        // this engine is only capable of processing small amounts
        if baggage.Amount > 10000 {
            return true, errors.New("amount too high")
        }
        return false, nil
    }),
)

baggage := &MyBaggage{UserID: "user123", Amount: 500}
output, err := policyEngine.Run(ctx, baggage)
```

## Step Implementation

```go
type myValidationStep struct{}

func (s *myValidationStep) GetName() string {
    return "validation"
}

func (s *myValidationStep) IsEligible(baggage MyBaggage) (bool, string) {
    return baggage.Amount > 0, "amount must be positive"
}

func (s *myValidationStep) PrepareDependencies(ctx context.Context, baggage *MyBaggage) error {
    // Fetch any required data, make API calls, etc.
    // This is the only place where side effects are allowed
    return nil
}

func (s *myValidationStep) ApplyPolicy(baggage MyBaggage) MyOutput {
    // Pure function - no side effects allowed
    if baggage.Amount < 100 {
        return MyOutput{Approved: false, Reason: "amount too small"}
    }
    return MyOutput{} // Non-terminal output, continue to next step
}

// similar implementation for myApprovalStep
```

## Configuration Options

- **WithName(name)**: Sets a name for the engine (used in logging)
- **WithBreaker(breakerFn)**: Sets a circuit breaker function

## Real-World Example

See `examples/policyengine_txns.go` for a complete credit card transaction
processing example that demonstrates:
- Multi-step validation (basic validation, risk assessment, approval)
- Feature flag integration for conditional step execution
- Time-based circuit breakers
- Comprehensive logging and tracing
- Integration with other goutils packages

## Key Features

- **Pure Policy Functions**: Policies themselves have no side effects, making them easy to test and reason about
- **Dependency Injection**: Dependencies are prepared separately from policy application
- **Conditional Execution**: Steps can be skipped based on runtime conditions
- **Circuit Breaker**: Engine can be disabled based on external conditions
- **Rich Logging**: Automatic logging with baggage metadata and execution traces
- **Type Safety**: Full generic type support for baggage and output types
- **Testability**: Interface-based design with mock support

## Testing

The engine provides mock implementations for testing:

```go
func TestMyPolicy(t *testing.T) {
    baggage := engine.NewMockEngineBaggage(t)
    baggage.On("GetLogFields").Return(map[string]any{})
    
    step := &myValidationStep{}
    output := step.ApplyPolicy(baggage)
    
    assert.True(t, output.IsTerminal())
}
```
