# Test Doubles

This is an exploration of test doubles in Go. I won't really demonstrate which
type of test double is useful in which scenarios -- the goal here is just to try
them all out. All of these are collectively referred to as "mocks."

The overarching context for this exploration is that we are building an API with
a DB layer, and are trying to test the DB layer appropriately.

## Real Implementations

The first, and perhaps most obvious, testing double is just a sandbox version of
the real database. This entails creating a connection to a testing database
(perhaps an in-memory one) and seeding data into it before invoking an API
endpoint that performs a single action on the data.

In our example, we:
- connect to the DB
- seed users
- spin up the API server with the DB connection
- invoke the /list endpoint
- verify that the returned users are correct

## Fake Implementation

A close testing double is using fakes. The idea behind fakes is that we don't
want to use the actual resource being mocked (for example, it may be a service
provider who wouldn't appreciate us hitting their APIs every time we test a
change, even in a dedicated sandbox environment). Instead, we opt to create a
fake implementation that behaves as similarly as possible to the thing we're
mocking -- in the case of a database, this is fairly easy to do; in our case, we
do this using a map as an in-memory data store.

In our example, we:
- create a fake DB
- seed users
- spin up the API server with the DB connection
- invoke the /list endpoint
- verify that the returned users are correct

Admittedly, there's a small inconsistency in this test. In the real test, we
seeded data directly using SQL queries, while in the fake one, we did so using
the fake DB's `CreateUser` method. In the case of a database, this doesn't make
much of a difference, but one can imagine that in the case of service providers,
we would probably need to use their interface methods/APIs in both cases.

## Stubbed/Spy Implementations

These are often the most common types of mocks, especially in unit tests. Stubs
are essentially just instructions to some mocking library to return a specific
set of outputs given a specific set of inputs (where the specificity can vary
broadly). In our tests, we use a SQL mock library that satisfies the `*sql.DB`
interface, allowing us to use the same database interface that our real code
would use.

Really, this mock would make more sense when testing the `DB` interface, as it
mocks the SQL connection directly, allowing us to focus on testing the interface
itself. But we'll use it here anyway -- one can imagine that a more appropriate
mock here would be a mocked version of the `DB` interface as a whole.

I mentioned spies in the heading. Spies are more of a feature of stubs rather
than a different testing double entirely (spies could exist on fakes or even
real implementations too, technically). A spy essentially tracks expectations
for a mock, i.e. allows us to assert that specific method calls were made. This
is a useful way to ensure that a test isn't just passing in a fluke, as well as
to ensure that any branching behavior makes the right service calls.

In our example, we:
- create a stubbed connection
- set up our mock rows and expected calls
- create a real DB with the stubbed connection
- spin up the API server with the DB connection
- invoke the /list endpoint
- verify that the returned users are correct
