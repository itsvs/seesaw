package typednil

import "github.com/itsvs/seesaw/goutils/errors"

const (
	ErrNilPerson = errors.Constant("person ref is nil")
)

type Person struct {
	name    string
	friends []*Person
}

func (p *Person) GetFriends() []*Person {
	if p == nil {
		return nil
	}
	return p.friends
}

func (p *Person) AddFriend(o *Person) error {
	if p == nil {
		return errors.Wrap(ErrNilPerson, "attempted to add a friend to a nil person")
	}
	if o == nil {
		return errors.Wrap(ErrNilPerson, "attempted to a nil person as a friend")
	}
	p.friends = append(p.friends, o)
	return nil
}

func (p *Person) GetName() string {
	if p == nil {
		return ""
	}
	return p.name
}

func NewPerson(name string) *Person {
	return &Person{
		name: name,
	}
}
