# Go Utilities

This package is a collection of miscellaneous code snippets/features that I've
found useful while working with Golang. Some of these are things I've designed
myself, others are inspired by things I've seen/used, and others still are just
little experiments with different patterns/behaviors in Golang.

The different snippets are listed below, with links. Each relevant snippet has
its own README.

## Golang Patterns

[Test Doubles](doubles/README.md): an exploration of various types of test
doubles in Golang (specifically fakes and stubs)

[Typed Nils](typednil/README.md): a quick look at typed operations on `nil`s

## Utilities/Extensions

[Optionals](optional/README.md): nullable/unset primitives, useful in contexts
such as databases with nullable columns (where null is semantically distinct
from the zero value)

[Errors](errors/README.md): while Golang knows how to handle wrapped errors, it
doesn't actually expose a wrapping construct by default -- it also has no
out-of-the-box concept of constant errors; this extension adds both of these

[Tracing](tracing/README.md): instead of using `slog` (or your preferred logger)
everywhere across a codebase, it's generally useful to standardize logging logic
based on some config stored on contexts; additionally, it is _sometimes_ useful
to have a logger that has a predefined context, in scenarios where you don't
want your target code to use a context except for logging

## Libraries

[Flags](flags/README.md): rudimentary interface for flag-gating features in code

[Policy Engine](policyengine/README.md): battle-tested library for applying
atomic policies to some input to generate output -- includes things like a
killswitch for the engine, per-policy toggles, etc.
