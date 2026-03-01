# Rust-like Errors in Go

Error handling in Go allows the programmer to take some liberties with their
functions' return types. Functions that can error will typically have a function
signature/body like this:

```go
func MyFunc(succeed bool) (string, error) {
    if succeed {
        return "success!", nil
    } else {
        return "", errors.New("oops!")
    }
}
```

It's fair to assume that `MyFunc` will only ever return either a non-nil error
or a non-empty string. But inevitably, this is just an assumption. There's
nothing stopping a programmer from writing a function that returns _both_, such
as in cases where an error being returned does not preclude some sort of default
path for the function to take. For example:

```go
// SplitEvenlyIfPossible divides an input string into two equal halves. If this
// isn't possible (i.e. the string is of an odd length), then this function will
// return the entire string as both of its return values, along with an error.
func SplitEvenlyIfPossible(inp string) (string, string, error) {
    if len(inp) % 2 == 0 {
        return inp[:len(inp) / 2], inp[len(inp) / 2:], nil
    }
    return inp, inp, errors.New("could not evenly divide string")
}
```

This is not an entirely unreasonable function to have. Imagine that the user
doesn't care directly about this function, but instead a function that the user
calls uses this to split its final result before passing it back to the user.

```go
func DoSomething() (string, string, error) {
    var finalResult string
    // do something
    return SplitEvenlyIfPossible(finalResult)
}
```

If the user calls `DoSomething`, they would learn nothing about the final result
if `SplitEvenlyIfPossible` simply errored on `finalResult`s of odd length.

This isn't usually the case, though. More often than not, you really only want a
function to emit one possible codepath -- either a successful result, or an
erroneous one -- not multiple combinations of results. Using the paradigm above,
this isn't possible in Golang. But what would that even look like?

Rust, on the other hand, does have a solution to this. It provides a generic
`Result<T, E>`, where `T` is the type of the successful result, and `E` is the
error class. When writing a function that returns an implementation of `Result`,
you have exactly two options when writing a final statement: call `Ok(T)`, or
call `Err(E)`. For the caller of your function, this implies that your code
guarantees that it will only return one or the other.

```rust
mod result_demo {
    #[derive(Debug)]
    pub enum SplitError {
        OddLengthInput,
    }

    pub type SplitResult<'a> = Result<(&'a str, &'a str), SplitError>;

    pub fn split_evenly_if_possible<'a>(inp: &'a str) -> SplitResult<'a> {
        if inp.len() % 2 != 0 {
            Err(SplitError::OddLengthInput)
        } else {
            Ok((&inp[..inp.len() / 2], &inp[inp.len() / 2..]))
        }
    }
}

fn main() {
    match result_demo::split_evenly_if_possible("hi") {
        Err(why) => panic!("{:?}", why),
        Ok((p1, p2)) => {
            println!("{}{}", p1, p2)
        },
    }

    match result_demo::split_evenly_if_possible("hello") {
        Err(why) => panic!("{:?}", why),
        Ok((p1, p2)) => {
            println!("{}{}", p1, p2)
        },
    }
}
```

Please excuse the questionable Rust code (I am far from fluent in Rust), but I'm
hoping it's good enough to get the idea across: here, `split_evenly_if_possible`
is confined to either returning a `SplitError` or returning a tuple of strings.
There is no world in which this function could return both or neither.

Let's go back to Golang. Stepping away from our canonical `if err != nil`
paradigm, how would we go about implementing something similar to what Rust has?
At its core, the Rust behavior boils down to "this function will return one of
two types." It's not like this is impossible in Go, but it unfortunately doesn't
look quite as clean (because there's no equivalent for the `Result` generic).

```go
import "fmt"

type SplitResult interface{
    splitResult()
}

type SplitSuccess struct {
	SplitResult
    P1 string
    P2 string
}

func (*SplitSuccess) splitResult() { return nil }

type SplitError struct {
	SplitResult
	error
}

func (*SplitError) splitResult() { return nil }

func (*SplitError) Error() string {
	return "oops!"
}

func SplitEvenlyIfPossible(inp string) SplitResult {
	if len(inp) % 2 != 0 {
		return &SplitError{}
	}
	return &SplitSuccess{
        P1: inp[:len(inp) / 2],
        P2: inp[len(inp) / 2:],
    }
}

func main() {
	switch res := SplitEvenlyIfPossible("hi"); v := res.(type) {
	case SplitSuccess:
		fmt.Printf("%s%s\n", v.P1, v.P2)
	case SplitError:
		fmt.Println(v.Error())
	}

	switch res := SplitEvenlyIfPossible("hello"); v := res.(type) {
	case SplitSuccess:
		fmt.Printf("%s%s\n", v.P1, v.P2)
	case SplitError:
		fmt.Println(v.Error())
	}
}
```

This pattern actually already exists in Go. Not with errors, but with potential
multiple types in the same field. API frameworks like [`ogen`](https://ogen.dev/)
do this to represent APIs with multiple response types
(see [Interface Responses](https://ogen.dev/docs/concepts/interface_responses)).
This is pretty useful, since we _know_ the API will only return one of its many
possible responses. But in the context of errors, this might be slightly
overboard. It also kind of comes down to language semantics -- something like
this would be pretty standard in Rust (e.g. it's how you would implement an API
with multiple response types and errors in
[`axum`](https://docs.rs/axum/latest/axum/)), but you probably wouldn't want to
do this in Go because it's not what people _expect_.

But it made for a fun writeup, so I wrote this :).