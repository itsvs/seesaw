package policyengine_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	engine "github.com/itsvs/seesaw/goutils/policyengine"
)

func TestPolicyEngine(t *testing.T) {
	validBaggage := engine.NewMockEngineBaggage(t)
	validBaggage.On("GetLogFields").Return(map[string]any{})

	breaker := func(baggage *engine.MockEngineBaggage) (bool, error) {
		return true, assert.AnError
	}

	t.Run("Run", func(t *testing.T) {
		t.Run("without breaker", func(t *testing.T) {
			e := engine.New(
				[]engine.Step[*engine.MockEngineBaggage, *engine.MockStepOutput]{validTerminalStep(t)},
				engine.WithName(t.Name()),
			)

			output, err := e.Run(context.Background(), &validBaggage)
			assert.NoError(t, err)
			assert.Equal(t, []string{"valid_terminal_step"}, output.StepsRun)
			assert.Equal(t, "terminal_output", output.Output.String())
		})

		t.Run("with breaker", func(t *testing.T) {
			e := engine.New(
				[]engine.Step[*engine.MockEngineBaggage, *engine.MockStepOutput]{},
				engine.WithName(t.Name()),
				engine.WithBreaker(breaker),
			)

			output, err := e.Run(context.Background(), &validBaggage)
			assert.ErrorIs(t, err, assert.AnError)
			assert.Empty(t, output.StepsRun)
		})

		t.Run("with multiple steps", func(t *testing.T) {
			e := engine.New(
				[]engine.Step[*engine.MockEngineBaggage, *engine.MockStepOutput]{validNonTerminalStep(t), validTerminalStep(t)},
				engine.WithName(t.Name()),
			)

			output, err := e.Run(context.Background(), &validBaggage)
			assert.NoError(t, err)
			assert.Equal(t, []string{"valid_non_terminal_step", "valid_terminal_step"}, output.StepsRun)
			assert.Equal(t, "terminal_output", output.Output.String())
		})

		t.Run("with no terminal step", func(t *testing.T) {
			e := engine.New(
				[]engine.Step[*engine.MockEngineBaggage, *engine.MockStepOutput]{validNonTerminalStep(t)},
				engine.WithName(t.Name()),
			)

			output, err := e.Run(context.Background(), &validBaggage)
			assert.ErrorIs(t, err, engine.ErrNoTerminalOutput)
			assert.Equal(t, []string{"valid_non_terminal_step"}, output.StepsRun)
		})

		t.Run("with multiple steps where one is ineligible", func(t *testing.T) {
			e := engine.New(
				[]engine.Step[*engine.MockEngineBaggage, *engine.MockStepOutput]{validNonTerminalStep(t), ineligibleStep(t), validTerminalStep(t)},
				engine.WithName(t.Name()),
			)

			output, err := e.Run(context.Background(), &validBaggage)
			assert.NoError(t, err)
			assert.Equal(t, []string{"valid_non_terminal_step", "valid_terminal_step"}, output.StepsRun)
			assert.Equal(t, "terminal_output", output.Output.String())
		})

		t.Run("with step that fails to prepare dependencies", func(t *testing.T) {
			e := engine.New(
				[]engine.Step[*engine.MockEngineBaggage, *engine.MockStepOutput]{failedSetupStep(t)},
				engine.WithName(t.Name()),
			)

			output, err := e.Run(context.Background(), &validBaggage)
			assert.ErrorIs(t, err, assert.AnError)
			assert.Equal(t, []string{"failed_setup_step"}, output.StepsRun)
		})
	})

	t.Run("RunBypassBreaker", func(t *testing.T) {
		e := engine.New(
			[]engine.Step[*engine.MockEngineBaggage, *engine.MockStepOutput]{validTerminalStep(t)},
			engine.WithName(t.Name()),
			engine.WithBreaker(breaker),
		)

		output, err := e.RunBypassBreaker(context.Background(), &validBaggage)
		assert.NoError(t, err)
		assert.Equal(t, []string{"valid_terminal_step"}, output.StepsRun)
		assert.Equal(t, "terminal_output", output.Output.String())
	})
}

func terminalStepOutput(t *testing.T) *engine.MockStepOutput {
	terminalStepOutput := engine.NewMockStepOutput(t)
	terminalStepOutput.On("IsTerminal").Return(true).Maybe()
	terminalStepOutput.On("String").Return("terminal_output").Maybe()
	return terminalStepOutput
}

func nonTerminalStepOutput(t *testing.T) *engine.MockStepOutput {
	nonTerminalStepOutput := engine.NewMockStepOutput(t)
	nonTerminalStepOutput.On("IsTerminal").Return(false).Maybe()
	nonTerminalStepOutput.On("String").Return("non_terminal_output").Maybe()
	return nonTerminalStepOutput
}

func validTerminalStep(t *testing.T) *engine.MockStep[*engine.MockEngineBaggage, *engine.MockStepOutput] {
	validTerminalStep := engine.NewMockStep[*engine.MockEngineBaggage, *engine.MockStepOutput](t)
	validTerminalStep.On("GetName").Return("valid_terminal_step")
	validTerminalStep.On("IsEligible", mock.Anything).Return(true, "")
	validTerminalStep.On("PrepareDependencies", mock.Anything, mock.Anything).Return(nil)
	validTerminalStep.On("ApplyPolicy", mock.Anything).Return(terminalStepOutput(t))
	return validTerminalStep
}

func validNonTerminalStep(t *testing.T) *engine.MockStep[*engine.MockEngineBaggage, *engine.MockStepOutput] {
	validNonTerminalStep := engine.NewMockStep[*engine.MockEngineBaggage, *engine.MockStepOutput](t)
	validNonTerminalStep.On("GetName").Return("valid_non_terminal_step")
	validNonTerminalStep.On("IsEligible", mock.Anything).Return(true, "")
	validNonTerminalStep.On("PrepareDependencies", mock.Anything, mock.Anything).Return(nil)
	validNonTerminalStep.On("ApplyPolicy", mock.Anything).Return(nonTerminalStepOutput(t))
	return validNonTerminalStep
}

func ineligibleStep(t *testing.T) *engine.MockStep[*engine.MockEngineBaggage, *engine.MockStepOutput] {
	ineligibleStep := engine.NewMockStep[*engine.MockEngineBaggage, *engine.MockStepOutput](t)
	ineligibleStep.On("GetName").Return("ineligible_step")
	ineligibleStep.On("IsEligible", mock.Anything).Return(false, "ineligible")
	return ineligibleStep
}

func failedSetupStep(t *testing.T) *engine.MockStep[*engine.MockEngineBaggage, *engine.MockStepOutput] {
	failedSetupStep := engine.NewMockStep[*engine.MockEngineBaggage, *engine.MockStepOutput](t)
	failedSetupStep.On("GetName").Return("failed_setup_step")
	failedSetupStep.On("IsEligible", mock.Anything).Return(true, "")
	failedSetupStep.On("PrepareDependencies", mock.Anything, mock.Anything).Return(assert.AnError)
	return failedSetupStep
}
