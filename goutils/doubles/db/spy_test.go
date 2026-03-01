package db

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDB_Spy(t *testing.T) {
	t.Run("mock DB with spy assertions", func(t *testing.T) {
		t.Run("ListUsers", func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)

			defer db.Close()

			rows := mock.NewRows([]string{"id", "name", "email"}).
				AddRow("1", "adam", "adam@example.com").
				AddRow("2", "bill", "bill@example.com")

			mock.ExpectQuery("SELECT").WithoutArgs().WillReturnRows(rows)

			testdb := NewDB(db)
			runListUsersTest(t, testdb)

			assert.NoError(t, mock.ExpectationsWereMet())
		})

		t.Run("GetUserById", func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)

			defer db.Close()

			rows := mock.NewRows([]string{"id", "name", "email"}).
				AddRow("1", "adam", "adam@example.com")

			mock.ExpectQuery("SELECT").WithArgs("1").WillReturnRows(rows)

			testdb := NewDB(db)
			runGetUserByIdTest(t, testdb)

			assert.NoError(t, mock.ExpectationsWereMet())
		})

		t.Run("CreateUser", func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)

			defer db.Close()

			rows := mock.NewRows([]string{"id", "name", "email"}).
				AddRow("1", "adam", "adam@example.com")

			mock.ExpectBegin()
			mock.ExpectQuery("INSERT").WithArgs("1", "adam", "adam@example.com").WillReturnRows(rows)
			mock.ExpectCommit()

			mock.ExpectQuery("SELECT").WithArgs("1").WillReturnRows(rows)

			testdb := NewDB(db)
			runCreateUserTest(t, testdb)

			assert.NoError(t, mock.ExpectationsWereMet())
		})

		t.Run("UpdateUser", func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)

			defer db.Close()

			rows := mock.NewRows([]string{"id", "name", "email"}).
				AddRow("1", "ally", "ally@example.com")

			mock.ExpectBegin()
			mock.ExpectQuery("UPDATE").WithArgs("ally", "ally@example.com", "1").WillReturnRows(rows)
			mock.ExpectCommit()

			mock.ExpectQuery("SELECT").WithArgs("1").WillReturnRows(rows)

			testdb := NewDB(db)
			runUpdateUserTest(t, testdb)

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	})
}
