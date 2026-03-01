package examples

import (
	"context"
	"fmt"
	"time"

	"github.com/itsvs/seesaw/goutils/errors"
	"github.com/itsvs/seesaw/goutils/flags"
	"github.com/itsvs/seesaw/goutils/optional"
	engine "github.com/itsvs/seesaw/goutils/policyengine"
	"github.com/itsvs/seesaw/goutils/tracing"
)

const (
	FlagGenericBreakerKey          = "txn-engine-enabled"
	FlagTimeBasedBreakerMinutesKey = "txn-engine-break-if-older-than"
	FlagBasicValidationEnabledKey  = "txn-engine-basic-validation-enabled"
	FlagAmountThresholdKey         = "txn-engine-amount-threshold"
)

// TransactionBaggage represents a credit card transaction to be processed:
// - Amount: Transaction amount in dollars (positive for charges, negative for refunds)
// - MerchantID: Unique identifier for the merchant
// - CardNumber: Credit card number (masked in logs)
// - TransactionID: Unique identifier for this transaction
// - CustomerRating: Risk score from 1-100 (higher is better)
// - Timestamp: When the transaction was initiated
//
// The engine processes transactions through multiple steps:
// 1. Basic Validation
//   - Validates transaction amount is non-zero (allows negative for refunds)
//   - Ensures card number format is valid
//   - Declines if either of the above checks fail
//   - Doesn't return a definitive approval/decline otherwise
//
// 2. Risk Assessment (for transactions > $10,000)
//   - Evaluates customer risk rating
//   - Only runs for high-value transactions
//   - Declines if customer rating < 60
//   - Doesn't return a definitive approval/decline otherwise
//
// 3. Formal Approval
//   - Final step that provides definitive approval
//   - Only runs if all previous steps pass
//   - Approves the transaction
//
// The engine includes a circuit breaker that stops processing if:
// - Transaction is more than 5 minutes old
//
// Each step can return one of three states:
// - Valid approval (true): Transaction is definitively approved
// - Valid approval (false): Transaction is definitively declined
// - Invalid approval: Transaction should continue to next step
type TransactionBaggage struct {
	Amount         float64
	MerchantID     string
	CardNumber     string
	TransactionID  string
	CustomerRating int // 1-100 risk score
	Timestamp      time.Time

	FlagsClient flags.Interface
	tracer      tracing.WithCtx
}

func (t TransactionBaggage) GetLogFields() map[string]any {
	return map[string]any{
		"transaction_id": t.TransactionID,
		"merchant_id":    t.MerchantID,
		"amount":         t.Amount,
		"timestamp":      t.Timestamp,
	}
}

type TransactionOutput struct {
	Approved optional.Bool
	Reason   string
}

func (o TransactionOutput) String() string {
	if !o.Approved.IsSet() {
		return "Transaction in progress"
	}
	if o.Approved.MustGet() {
		return fmt.Sprintf("Transaction approved: %s", o.Reason)
	}
	return fmt.Sprintf("Transaction declined: %s", o.Reason)
}

func (o TransactionOutput) IsTerminal() bool {
	return o.Approved.IsSet() // Stop if we have a definitive approval/decline
}

type transactionStep struct {
	name         string
	eligibleFunc func(TransactionBaggage) (bool, string)
	setupFunc    func(context.Context, *TransactionBaggage) error
	applyFunc    func(TransactionBaggage) TransactionOutput
}

func (s *transactionStep) GetName() string {
	return s.name
}

func (s *transactionStep) IsEligible(baggage TransactionBaggage) (bool, string) {
	return s.eligibleFunc(baggage)
}

func (s *transactionStep) PrepareDependencies(ctx context.Context, baggage *TransactionBaggage) error {
	return s.setupFunc(ctx, baggage)
}

func (s *transactionStep) ApplyPolicy(baggage TransactionBaggage) TransactionOutput {
	return s.applyFunc(baggage)
}

func TransactionPolicyEngine(ctx context.Context, tx *TransactionBaggage) {
	// Define policy steps
	var steps []engine.Step[TransactionBaggage, TransactionOutput]

	// Step 1: Basic validation
	steps = append(steps, &transactionStep{
		name: "Basic Validation",
		eligibleFunc: func(b TransactionBaggage) (bool, string) {
			if b.FlagsClient.GetBool(FlagBasicValidationEnabledKey, true) {
				return true, ""
			}
			return false, "flag returned false"
		},
		setupFunc: func(ctx context.Context, b *TransactionBaggage) error {
			b.tracer = tracing.WithContext(ctx)
			return nil
		},
		applyFunc: func(b TransactionBaggage) TransactionOutput {
			b.tracer.Info("Validating transaction", tracing.Kvs{
				"amount":          b.Amount,
				"len_card_number": len(b.CardNumber),
			})
			if b.Amount == 0 {
				return TransactionOutput{
					Approved: optional.NewBool(false),
					Reason:   "transaction amount cannot be zero",
				}
			}
			if len(b.CardNumber) < 15 {
				return TransactionOutput{
					Approved: optional.NewBool(false),
					Reason:   "invalid card number",
				}
			}
			return TransactionOutput{}
		},
	})

	// Step 2: Risk Assessment
	steps = append(steps, &transactionStep{
		name: "Risk Assessment",
		eligibleFunc: func(b TransactionBaggage) (bool, string) {
			threshold := b.FlagsClient.GetFloat(FlagAmountThresholdKey, 10000)
			if b.Amount > threshold {
				return true, ""
			}
			return false, "amount below flag-specified risk threshold"
		},
		setupFunc: func(ctx context.Context, b *TransactionBaggage) error {
			b.tracer = tracing.WithContext(ctx)
			return nil
		},
		applyFunc: func(b TransactionBaggage) TransactionOutput {
			b.tracer.Info("Performing risk assessment", tracing.Kvs{
				"amount":          b.Amount,
				"customer_rating": b.CustomerRating,
			})
			if b.CustomerRating < 60 {
				return TransactionOutput{
					Approved: optional.NewBool(false),
					Reason:   "high risk customer",
				}
			}
			return TransactionOutput{}
		},
	})

	// Step 3: Formal Approval
	steps = append(steps, &transactionStep{
		name: "Formal Approval",
		eligibleFunc: func(b TransactionBaggage) (bool, string) {
			return true, "" // Always eligible if previous steps passed
		},
		setupFunc: func(ctx context.Context, b *TransactionBaggage) error {
			b.tracer = tracing.WithContext(ctx)
			return nil
		},
		applyFunc: func(b TransactionBaggage) TransactionOutput {
			b.tracer.Info("Formally approving transaction", tracing.Kvs{
				"amount": b.Amount,
			})
			return TransactionOutput{
				Approved: optional.NewBool(true),
				Reason:   "transaction formally approved",
			}
		},
	})

	// Create engine instance
	txEngine := engine.New(
		steps,
		engine.WithName("credit-card-transaction-engine"),
		engine.WithBreaker(func(b TransactionBaggage) (bool, error) {
			// Break if generic breaker evaluates to false
			if !b.FlagsClient.GetBool(FlagGenericBreakerKey, true) {
				return true, errors.Constant("breaker flag active")
			}

			// Break if transaction is too old
			expirationMinutes := b.FlagsClient.GetFloat(FlagTimeBasedBreakerMinutesKey, 5)
			if time.Since(b.Timestamp) > time.Duration(expirationMinutes)*time.Minute {
				return true, errors.Constant("transaction expired")
			}
			return false, nil
		}),
	)

	// Run engine
	output, err := txEngine.Run(ctx, tx)
	if err != nil {
		tracing.Error(ctx, "Transaction processing failed", tracing.Kvs{
			"error": err.Error(),
		})
		return
	}

	tracing.Info(ctx, "Transaction processed successfully", tracing.Kvs{
		"result":    output.Output.String(),
		"steps_run": output.StepsRun,
	})
}
