# Error Handling

This package wraps the default `errors` package's functions and introduces two
error utilities.

## Wrapped Errors

Go has built-in support for errors that wrap other errors. However, it doesn't
actually expose any functionality for _creating_ such errors -- only for
unwrapping them once they've been created. This package has a new (hidden)
`wrapError` type, which contains a wrapped error along with a message for the
current error. This is useful for stack traces, e.g.:

```go
// GetStaffMemberByPosiiton("eladta")
err := errors.New(fmt.Sprintf("invalid position %s", position))
// GetCourseLead("cs101")
err = errors.Wrap(err, fmt.Sprintf("couldn't get %s course lead", course))
// GetDepartmentLeads("compsci")
err = errors.Wrap(err, fmt.Sprintf("couldn't get %s dept leads", dept))
```

The final error message, if we called `err.Error()`, would be:

```go
"couldn't get compsci dept leads: couldn't get cs101 course lead: invalid position eladta"
```

This is a pretty descriptive error message, as it lets you follow the call
sequence up (or down) the stack until you find the culprit. Wrapping, when used
appropriately, can make tracing and debugging much easier.

## Error KVs

The above is already quite helpful, but if you're trying to look at an aggregate
view of the various errors your application throws (e.g. in Sentry), it's a bit
hard to set up a rule that detects these specific errors, since they have values
in them that change constantly ("compsci", "cs101", "eladta").

One way to deal with this is to add metadata to error objects. Things like the
fields that caused an issue (or just are useful for tracing) could go in this
metadata, allowing the error messages themselves to be generic (and therefore
easily searchable).

```go
// GetStaffMemberByPosiiton("eladta")
err := errors.New("invalid position", errors.Kv("position", position))
// GetCourseLead("cs101")
err = errors.Wrap(err, "couldn't get course lead", errors.Kv("course", course))
// GetDepartmentLeads("compsci")
err = errors.Wrap(err, "couldn't get dept leads", errors.Kv("dept", dept))
```

Now, the error message itself looks like this:

```go
"couldn't get dept leads: couldn't get course lead: invalid position"
```

At the same time, the error has additional useful data:

```go
// errors.Kvs(err)
{
    "dept": "compsci",
    "course": "cs101",
    "position": "eladta"
}
```

One can imagine this being useful if emitted to a logging engine, for instance
to determine whether specific inputs are causing an issue.

There's a lot more that goes into errors than just stacktrace and input logging,
so these utilities are in no way comprehensive. But I have found that they make
errors a bit more useful, so I figured I'd share a rudimentary implementation of
some of them.
