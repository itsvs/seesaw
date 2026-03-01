package db

import (
	"context"
	"database/sql"
)

type DB interface {
	ListUsers(ctx context.Context) ([]*User, error)
	GetUserById(ctx context.Context, id string) (*User, error)
	CreateUser(ctx context.Context, u *User) error
	UpdateUser(ctx context.Context, u *User) error
}

type db struct {
	conn *sql.DB
}

func NewDB(conn *sql.DB) DB {
	return &db{
		conn: conn,
	}
}

func (db *db) ListUsers(ctx context.Context) ([]*User, error) {
	res, err := db.conn.QueryContext(ctx, "SELECT * FROM users")
	if err != nil {
		return nil, err
	}

	var users []*User
	for res.Next() {
		u := NewUser("", "", "")
		err = res.Scan(&u.Id, &u.Name, &u.Email)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}

	return users, nil
}

func (db *db) GetUserById(ctx context.Context, id string) (*User, error) {
	res, err := db.conn.QueryContext(ctx, `SELECT * FROM users WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}

	u := NewUser("", "", "")
	res.Next()
	err = res.Scan(&u.Id, &u.Name, &u.Email)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (db *db) CreateUser(ctx context.Context, u *User) error {
	tx, err := db.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	_, err = tx.QueryContext(ctx, `INSERT INTO users (id, name, email) VALUES (?, ?, ?)`, u.Id, u.Name, u.Email)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (db *db) UpdateUser(ctx context.Context, u *User) error {
	tx, err := db.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	_, err = tx.QueryContext(ctx, `UPDATE users SET name = ?, email = ? WHERE id = ?`, u.Name, u.Email, u.Id)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}
