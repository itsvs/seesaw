package cmd

import (
	"context"
	"time"

	"github.com/itsvs/seesaw/goutils/examples"
	"github.com/itsvs/seesaw/goutils/flags"
	"github.com/spf13/cobra"
)

var policyEngineCmd = &cobra.Command{
	Use:   "policyengine",
	Short: "Runs a sample policy engine",
	Long:  `Runs a sample policy engine. See subcommands for more information.`,
}

var tx = &examples.TransactionBaggage{
	Amount:         5000.00,
	MerchantID:     "MERCH123",
	CardNumber:     "4532123456789012",
	TransactionID:  "TX789012",
	CustomerRating: 75,
	Timestamp:      time.Now(),
}

var policyEngineTxnsCmd = &cobra.Command{
	Use:   "txns",
	Short: "Runs the sample transactions policy engine",
	Long:  `Runs the sample transactions policy engine. This engine approves or declines transactions based on their parameters.`,
	Run: func(cmd *cobra.Command, args []string) {
		// initialize flags
		tx.FlagsClient = flags.New(map[string]any{
			examples.FlagGenericBreakerKey:          true,
			examples.FlagTimeBasedBreakerMinutesKey: 5,
			examples.FlagAmountThresholdKey:         10000,
			examples.FlagBasicValidationEnabledKey:  true,
		})

		ctx := context.Background()
		examples.TransactionPolicyEngine(ctx, tx)
	},
}

func init() {
	rootCmd.AddCommand(policyEngineCmd)
	policyEngineCmd.AddCommand(policyEngineTxnsCmd)
	policyEngineTxnsCmd.Flags().StringVarP(&tx.TransactionID, "txnid", "t", "TX789012", "The transaction ID")
	policyEngineTxnsCmd.Flags().StringVarP(&tx.MerchantID, "merchantid", "m", "MERCH123", "The merchant ID")
	policyEngineTxnsCmd.Flags().StringVarP(&tx.CardNumber, "cardnumber", "n", "4532123456789012", "The card number")
	policyEngineTxnsCmd.Flags().Float64VarP(&tx.Amount, "amount", "a", 5000.00, "The transaction amount")
	policyEngineTxnsCmd.Flags().IntVarP(&tx.CustomerRating, "rating", "r", 75, "The customer rating")
}
