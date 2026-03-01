# Optional Primitives

Go, like most modern languages, exposes primitives that come with default/zero
values. Specifically, these are:

```go
var default bool
default == false

var default int
default == 0

var default string
default == ""
```

There are some scenarios in which you may want to distinguish between these zero
values and an "absent" value. For instance, say you have an API endpoint that a
caller can invoke to update fields on an object. Some of these fields may be
primitives, and as such, you don't want to overwrite them unless the caller has
explicitly asked you to. See the following requests:

```sh
curl /update --json '{ "user_id": 27, "name": "Billy Joel", "is_verified": false }'
curl /update --json '{ "user_id": 27, "name": "Billy Joel", "is_verified": true }'
curl /update --json '{ "user_id": 27, "name": "Billy Joel" }'
```

In the first and second requests, you are explicitly trying to set the user's
name and verification status. However, in the third request, you are only trying
to set their name -- you don't want anything to change about their verification
status. You've indicated this by not passing in the `is_verified` parameter at
all, but how does the server distinguish this?

Enter `optional`, which allows the server to treat this parameter as a nullable
object instead of a primitive. If the server sees that `is_verified` was set,
then it can parse it into the request object as `optional.NewBool(value)`, which
the handler can then interpret appropriately. No value set? No problem, the
handler can verify this by calling `req.IsVerified.IsSet()` and make no changes
if this returns `false`.

The specific example can be resolved differently as well, e.g. by having a
different endpoint to update each specific part of a user, or by requiring a
complete user object every time. As with anything, context matters -- if we're
using POST requests, either of these are fine alternatives. But, if we're using
PATCH requests, we should probably try to adhere to the HTTP standard and allow
true partial updates. This library facilitates something like that.

