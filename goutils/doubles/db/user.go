package db

type User struct {
	Id    string `sql:"id" json:"id"`
	Name  string `sql:"name" json:"name"`
	Email string `sql:"email" json:"email"`
}

func NewUser(id, name, email string) *User {
	return &User{
		Id:    id,
		Name:  name,
		Email: email,
	}
}

func (u *User) GetId() string {
	return u.Id
}

func (u *User) GetName() string {
	return u.Name
}

func (u *User) GetEmail() string {
	return u.Email
}
