package db

import (
	"testing"

	_ "modernc.org/sqlite"
)

func TestDB_Fake(t *testing.T) {
	t.Run("fake DB", func(t *testing.T) {
		t.Run("ListUsers", func(t *testing.T) {
			testdb := NewFakeDB()
			testdb.(*fakedb).users["1"] = &User{"1", "adam", "adam@example.com"}
			testdb.(*fakedb).users["2"] = &User{"2", "bill", "bill@example.com"}

			runListUsersTest(t, testdb)
		})

		t.Run("GetUserById", func(t *testing.T) {
			testdb := NewFakeDB()
			testdb.(*fakedb).users["1"] = &User{"1", "adam", "adam@example.com"}
			testdb.(*fakedb).users["2"] = &User{"2", "bill", "bill@example.com"}

			runGetUserByIdTest(t, testdb)
		})

		t.Run("CreateUser", func(t *testing.T) {
			testdb := NewFakeDB()

			runCreateUserTest(t, testdb)
		})

		t.Run("UpdateUser", func(t *testing.T) {
			testdb := NewFakeDB()
			testdb.(*fakedb).users["1"] = &User{"1", "adam", "adam@example.com"}
			testdb.(*fakedb).users["2"] = &User{"2", "bill", "bill@example.com"}

			runUpdateUserTest(t, testdb)
		})
	})
}
