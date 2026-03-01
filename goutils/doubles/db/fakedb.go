package db

import (
	"context"
	"database/sql"
)

type fakedb struct {
	users map[string]*User
}

func NewFakeDB() DB {
	return &fakedb{
		users: make(map[string]*User),
	}
}

func (db *fakedb) ListUsers(ctx context.Context) ([]*User, error) {
	var users []*User
	for _, u := range db.users {
		users = append(users, u)
	}
	return users, nil
}

func (db *fakedb) GetUserById(ctx context.Context, id string) (*User, error) {
	if u, ok := db.users[id]; ok {
		return u, nil
	}
	return nil, sql.ErrNoRows
}

func (db *fakedb) CreateUser(ctx context.Context, u *User) error {
	db.users[u.Id] = u
	return nil
}

func (db *fakedb) UpdateUser(ctx context.Context, u *User) error {
	if _, ok := db.users[u.Id]; !ok {
		return sql.ErrNoRows
	}
	db.users[u.Id] = u
	return nil
}
