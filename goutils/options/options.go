package options

// Person represents a human being with limited properties, specifically a
// name and a list of emails that belong to them.
type Person struct {
	Name   string
	Emails []string
}

// createPersonOption represents options that can be passed into CreatePerson
// in order to set some data about the person being created.
type createPersonOption interface {
	apply(p *Person)
}

// CreatePerson creates and returns a Person, with no values set by default.
// You can pass in options to provide data about the Person.
func CreatePerson(opts ...createPersonOption) *Person {
	p := &Person{}
	for _, opt := range opts {
		opt.apply(p)
	}
	return p
}

type withNameOption struct {
	name string
}

func (opt *withNameOption) apply(p *Person) {
	p.Name = opt.name
}

// WithName returns an option that sets a Person's Name.
func WithName(name string) createPersonOption {
	return &withNameOption{name}
}

type withEmailOption struct {
	email string
}

func (opt *withEmailOption) apply(p *Person) {
	p.Emails = append(p.Emails, opt.email)
}

// WithEmail returns an option that appends an email to a Person's Emails.
func WithEmail(email string) createPersonOption {
	return &withEmailOption{email}
}
