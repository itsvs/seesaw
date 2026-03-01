package examples

import (
	"context"

	"github.com/itsvs/seesaw/goutils/optional"
	"github.com/itsvs/seesaw/goutils/tracing"
)

// the optional package is fairly straightforward. it just wraps a primitive
// value with a flag indicating whether the value is set.

// here's an example of how to use it.

func ExampleOptional(ctx context.Context) {
	// create an optional value
	opt := optional.NewBool(true)

	// check if the value is set
	if opt.IsSet() {
		tracing.Info(ctx, "optional boolean value is set", tracing.Kvs{})
	} else {
		tracing.Info(ctx, "optional boolean value is not set", tracing.Kvs{})
	}

	// get the value
	value := opt.MustGet()
	tracing.Info(ctx, "emitting optional boolean value", tracing.Kvs{"value": value})
}
