# Feature Flags

The software development lifecycle involves a variety of flag-gated feature
testing/releases. This library exposes an interface for fetching your flag
values at runtime, but more importantly, it exposes a wrapping interface that
can be used for testing. This interface lets you specify a value for a feature
flag that'll be cleaned up after the relevant test has finished running, which
means you don't have to worry about initializing a new client correctly for each
test in your suite. Just do something like this:

```go
func TestMyFunction(t *testing.T) {
    flags := NewForTesting(nil) // initial flag values (none)
    
    for _, numThreads := range []float64{1, 2, 5, 17} {
        t.Run(fmt.Sprintf("with flag set to %f", numThreads), func (t *testing.T) {
            flags.SetFloatForTest(t, "num-max-threads", numThreads)
            // ... rest of test ...
        })
    }
}
```

This way, your code will always read the correct value _or the default value_
(if appropriate) -- it will never read a stale value from an old test. Unless,
of course, you're running tests in parallel -- there isn't a good solution for
that aside from creating new flags clients...
