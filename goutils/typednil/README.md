# Typed Nils in Go

By default, `nil` is not a typed value. However, in Go, it is possible to assign
`nil`s to explicitly-typed variables, which allows context-based nil handling.
For example, the following code would not work:

```go
person := nil
person.GetFriends()
```

Since there is no implied or specified type for `person`, Golang will panic when
trying to invoke a method on it. However, the following code is totally fine:

```go
var person *Person
person.GetFriends()
```

In both cases, `person` is `nil`. In the latter case, because we've specified
that `person` is a `*Person`, Golang can invoke `GetFriends` on a `nil` object,
deferring to the method to handle a `nil` value appropriately.

This is pretty useful in contexts where, for one reason or another, you don't
want to have to check for `nil`s explicitly over and over. One example of this
is in generated protobuf messages -- you'll likely have nested structs in a
protobuf message, and it's kind of a pain to have to check `nil`s over and over
(because nearly everything is a pointer, the default zero-value is `nil`).

Generated protobuf messages in Go generally have getter methods for this exact
scenario. It's common to have accessor code that looks like this:

```go
var uni *University
uni.
    GetCollegeByName("engineering").
    GetDepartmentBySlug("compsci").
    GetCourseByCode("cs101").
    GetStaffMemberByPosition("leadta").
    GetName()
```

You can imagine the series of methods working as follows:

```go
func (u *University) GetCollegeByName(name string) *College {
    if u == nil { return nil }
    return u.collegesByName[name]
}

func (c *College) GetDepartmentBySlug(slug string) *Department {
    if c == nil { return nil }
    return c.departmentsBySlug[slug]
}

func (d *Department) GetCourseByCode(code string) *Course {
    if d == nil { return nil }
    return d.coursesByCode[code]
}

func (c *Course) GetStaffMemberByPosition(position string) *Person {
    if c == nil { return nil }
    return c.staffByPosition[position]
}

func (p *Person) GetName() string {
    if p == nil { return "" }
    return p.name
}
```

Depending on your use case, this is infinitely better than having to check for
`nil`s along the way. In a way, it's a way for these types to defer error logic
to the caller -- if you try to work down this path, the types won't return an
error to you that you may not care about, letting you decide how many calls to
chain together before looking for a potentially-relevant error to throw.

You may, for instance, care to throw an error if the department requested does
not exist, but you may not care to throw one for a nonexistent college or for a
nonexistent course within a department. You can split your chain of calls based
on this, giving you a lot more flexibility and not requiring you to litter your
code with `if err != nil` for irrelevant `NotFound`s.
