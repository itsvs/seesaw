package policyengine

import (
	"context"
	"maps"

	"github.com/itsvs/seesaw/goutils/errors"
	"github.com/itsvs/seesaw/goutils/tracing"
)

// This file contains an implementation of the Engine interface. See the
// interface.go file for more information.

type policyEngine[B EngineBaggage, O StepOutput] struct {
	name    string
	steps   []Step[B, O]
	breaker BreakerFn[B]
}

func (p *policyEngine[B, _]) IsBreakerTripped(baggage B) (bool, error) {
	if p.breaker == nil {
		return false, nil
	}
	return p.breaker(baggage)
}

func (p *policyEngine[B, O]) Run(ctx context.Context, baggage *B) (output EngineOutput[B, O], err error) {
	if tripped, reason := p.IsBreakerTripped(*baggage); tripped {
		return output, errors.Wrap(reason, "breaker tripped")
	}

	return p.RunBypassBreaker(ctx, baggage)
}

func (p *policyEngine[B, O]) RunBypassBreaker(ctx context.Context, baggage *B) (output EngineOutput[B, O], err error) {
	defer func() {
		fields := tracing.Kvs{
			"engine":    p.name,
			"steps_run": output.StepsRun,
		}

		maps.Copy(fields, (*baggage).GetLogFields())

		if err != nil {
			fields["error"] = err
		} else {
			fields["output"] = output.Output.String()
		}

		tracing.Info(ctx, "policy engine finished running", fields)
	}()

	for _, step := range p.steps {
		if eligible, reason := step.IsEligible(*baggage); !eligible {
			tracing.Info(ctx, "skipping policy engine step", tracing.Kvs{
				"engine": p.name,
				"step":   step.GetName(),
				"reason": reason,
			})
			continue
		}

		output.StepsRun = append(output.StepsRun, step.GetName())

		if err := step.PrepareDependencies(ctx, baggage); err != nil {
			return output, err
		}

		if stepOutput := step.ApplyPolicy(*baggage); stepOutput.IsTerminal() {
			output.Output = stepOutput
			return output, nil
		}
	}

	return output, errors.Wrap(ErrNoTerminalOutput, p.name)
}

// New creates a new policy engine. At minimum, a list of steps must be provided.
// Additional options may be provided to configure the engine; see options.go
// for more information on the available options.
func New[B EngineBaggage, O StepOutput](steps []Step[B, O], options ...EngineOption) Engine[B, O] {
	engine := &policyEngine[B, O]{
		steps: steps,
	}

	for _, option := range options {
		switch option := option.(type) {
		case engineName:
			engine.name = string(option)
		case engineBreaker[B]:
			engine.breaker = BreakerFn[B](option)
		}
	}

	return engine
}
