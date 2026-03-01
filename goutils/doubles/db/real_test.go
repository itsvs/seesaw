package db

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

func TestDB_Real(t *testing.T) {
	t.Run("real DB with in-memory SQL connection", func(t *testing.T) {
		t.Run("ListUsers", func(t *testing.T) {
			db, err := sql.Open("sqlite", ":memory:")
			require.NoError(t, err)

			defer db.Close()

			tx, err := db.BeginTx(t.Context(), nil)
			require.NoError(t, err)

			_, err = tx.QueryContext(t.Context(), "CREATE TABLE users (id VARCHAR(255), name VARCHAR(255), email VARCHAR(255))")
			require.NoError(t, err)

			_, err = tx.QueryContext(t.Context(), "INSERT INTO users (id, name, email) VALUES ('1', 'adam', 'adam@example.com')")
			require.NoError(t, err)

			_, err = tx.QueryContext(t.Context(), "INSERT INTO users (id, name, email) VALUES ('2', 'bill', 'bill@example.com')")
			require.NoError(t, err)

			err = tx.Commit()
			require.NoError(t, err)

			testdb := NewDB(db)
			runListUsersTest(t, testdb)
		})

		t.Run("GetUserById", func(t *testing.T) {
			db, err := sql.Open("sqlite", ":memory:")
			require.NoError(t, err)

			defer db.Close()

			tx, err := db.BeginTx(t.Context(), nil)
			require.NoError(t, err)

			_, err = tx.QueryContext(t.Context(), "CREATE TABLE users (id VARCHAR(255), name VARCHAR(255), email VARCHAR(255))")
			require.NoError(t, err)

			_, err = tx.QueryContext(t.Context(), "INSERT INTO users (id, name, email) VALUES ('1', 'adam', 'adam@example.com')")
			require.NoError(t, err)

			_, err = tx.QueryContext(t.Context(), "INSERT INTO users (id, name, email) VALUES ('2', 'bill', 'bill@example.com')")
			require.NoError(t, err)

			err = tx.Commit()
			require.NoError(t, err)

			testdb := NewDB(db)
			runGetUserByIdTest(t, testdb)
		})

		t.Run("CreateUser", func(t *testing.T) {
			db, err := sql.Open("sqlite", ":memory:")
			require.NoError(t, err)

			defer db.Close()

			tx, err := db.BeginTx(t.Context(), nil)
			require.NoError(t, err)

			_, err = tx.QueryContext(t.Context(), "CREATE TABLE users (id VARCHAR(255), name VARCHAR(255), email VARCHAR(255))")
			require.NoError(t, err)

			err = tx.Commit()
			require.NoError(t, err)

			testdb := NewDB(db)
			runCreateUserTest(t, testdb)
		})

		t.Run("UpdateUser", func(t *testing.T) {
			db, err := sql.Open("sqlite", ":memory:")
			require.NoError(t, err)

			defer db.Close()

			tx, err := db.BeginTx(t.Context(), nil)
			require.NoError(t, err)

			_, err = tx.QueryContext(t.Context(), "CREATE TABLE users (id VARCHAR(255), name VARCHAR(255), email VARCHAR(255))")
			require.NoError(t, err)

			_, err = tx.QueryContext(t.Context(), "INSERT INTO users (id, name, email) VALUES ('1', 'adam', 'adam@example.com')")
			require.NoError(t, err)

			_, err = tx.QueryContext(t.Context(), "INSERT INTO users (id, name, email) VALUES ('2', 'bill', 'bill@example.com')")
			require.NoError(t, err)

			err = tx.Commit()
			require.NoError(t, err)

			testdb := NewDB(db)
			runUpdateUserTest(t, testdb)
		})
	})
}
