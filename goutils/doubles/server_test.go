package doubles

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/itsvs/seesaw/goutils/doubles/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

func runListUsersTest(t *testing.T, s *server) {
	router := s.setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/list", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `[{"id":"1","name":"adam","email":"adam@example.com"},{"id":"2","name":"bill","email":"bill@example.com"}]`, w.Body.String())
}

func runGetUserByIdTest(t *testing.T, s *server) {
	router := s.setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/get/1", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"id":"1","name":"adam","email":"adam@example.com"}`, w.Body.String())
}

func TestWithReal(t *testing.T) {
	t.Run("ListUsers", func(t *testing.T) {
		testdb, err := sql.Open("sqlite", ":memory:")
		require.NoError(t, err)

		defer testdb.Close()

		tx, err := testdb.BeginTx(t.Context(), nil)
		require.NoError(t, err)

		_, err = tx.QueryContext(t.Context(), "CREATE TABLE users (id VARCHAR(255), name VARCHAR(255), email VARCHAR(255))")
		require.NoError(t, err)

		_, err = tx.QueryContext(t.Context(), "INSERT INTO users (id, name, email) VALUES ('1', 'adam', 'adam@example.com')")
		require.NoError(t, err)

		_, err = tx.QueryContext(t.Context(), "INSERT INTO users (id, name, email) VALUES ('2', 'bill', 'bill@example.com')")
		require.NoError(t, err)

		err = tx.Commit()
		require.NoError(t, err)

		s := &server{db: db.NewDB(testdb)}
		runListUsersTest(t, s)
	})

	t.Run("GetUserById", func(t *testing.T) {
		testdb, err := sql.Open("sqlite", ":memory:")
		require.NoError(t, err)

		defer testdb.Close()

		tx, err := testdb.BeginTx(t.Context(), nil)
		require.NoError(t, err)

		_, err = tx.QueryContext(t.Context(), "CREATE TABLE users (id VARCHAR(255), name VARCHAR(255), email VARCHAR(255))")
		require.NoError(t, err)

		_, err = tx.QueryContext(t.Context(), "INSERT INTO users (id, name, email) VALUES ('1', 'adam', 'adam@example.com')")
		require.NoError(t, err)

		_, err = tx.QueryContext(t.Context(), "INSERT INTO users (id, name, email) VALUES ('2', 'bill', 'bill@example.com')")
		require.NoError(t, err)

		err = tx.Commit()
		require.NoError(t, err)

		s := &server{db: db.NewDB(testdb)}
		runGetUserByIdTest(t, s)
	})
}

func TestWithFake(t *testing.T) {
	t.Run("ListUsers", func(t *testing.T) {
		testdb := db.NewFakeDB()
		err := testdb.CreateUser(t.Context(), db.NewUser("1", "adam", "adam@example.com"))
		require.NoError(t, err)
		err = testdb.CreateUser(t.Context(), db.NewUser("2", "bill", "bill@example.com"))
		require.NoError(t, err)

		s := &server{db: testdb}
		runListUsersTest(t, s)
	})

	t.Run("GetUserById", func(t *testing.T) {
		testdb := db.NewFakeDB()
		err := testdb.CreateUser(t.Context(), db.NewUser("1", "adam", "adam@example.com"))
		require.NoError(t, err)
		err = testdb.CreateUser(t.Context(), db.NewUser("2", "bill", "bill@example.com"))
		require.NoError(t, err)

		s := &server{db: testdb}
		runGetUserByIdTest(t, s)
	})
}

func TestWithStubSpy(t *testing.T) {
	t.Run("ListUsers", func(t *testing.T) {
		testdb, mock, err := sqlmock.New()
		require.NoError(t, err)

		defer testdb.Close()

		rows := mock.NewRows([]string{"id", "name", "email"}).
			AddRow("1", "adam", "adam@example.com").
			AddRow("2", "bill", "bill@example.com")

		mock.ExpectQuery("SELECT").WithoutArgs().WillReturnRows(rows)

		s := &server{db: db.NewDB(testdb)}
		runListUsersTest(t, s)

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("GetUserById", func(t *testing.T) {
		testdb, mock, err := sqlmock.New()
		require.NoError(t, err)

		defer testdb.Close()

		rows := mock.NewRows([]string{"id", "name", "email"}).
			AddRow("1", "adam", "adam@example.com").
			AddRow("2", "bill", "bill@example.com")

		mock.ExpectQuery("SELECT").WithArgs("1").WillReturnRows(rows)

		s := &server{db: db.NewDB(testdb)}
		runGetUserByIdTest(t, s)

		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
