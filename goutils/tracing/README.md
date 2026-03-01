# Tracing Wrappers

There are a variety of tracing libraries in Go, most of which have fairly
similar semantics. However, one thing they all have in common is that you
typically construct a logger instance that you then have to pass around to
emit logs.

In a real application, logging is fairly homogeneous, i.e. different parts of
your app won't generally emit logs any differently. They'll all have the same
formats, the same verbosity, etc.. As such, passing around something that is
essentially static adds unnecessary overhead to your application.

This package has an example of this -- upon initialization, a static logger is
created, which can be accessed from anywhere by invoking various functions in
this package.

## Contextless Tracing

While uncommon, there are a few design patterns in Go that are predicated on a
context being absent in a callstack. One example of this is in the
[../policyengine](Policy Engine)'s `ApplyPolicy` method, which is deliberately
missing access to a `context.Context` in order to enforce an inability to make
service calls (the original design here was for a system where interservice
communication in done via RPC, which in Go necessitates a context being passed
around). The general idea is that a policy's application should be contained
almost entirely to primitive code that reads exclusively from the engine's
baggage.

But the issue with that design is that, for most logging libraries, we would be
unable to emit any logs from `ApplyPolicy`. Perhaps that's desired -- a policy
should be so simple that logs might not even make sense. Still, this is an
unintended consequence of our choices, so I want to remedy it somehow.

The way that this package remedies that is by exposing a `WithContext` function,
which returns a wrapped version of the global logger instance that doesn't
require you to pass in a context to emit logs. Instead, the context passed in is
the context that gets used for any logs emitted through the returned instance.

Because this context cannot be modified, this should be using sparingly and in a
very limited way. Specifically, you should only instantiate this in a parent
function and use it in immediate child functions. Threading it down the stack
will mean you're just passing parent context down infinitely with no information
about any calls along the way.
