package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runListUsersTest(t *testing.T, db DB) {
	users, err := db.ListUsers(t.Context())
	require.NoError(t, err)

	assert.Len(t, users, 2)
}

func runGetUserByIdTest(t *testing.T, db DB) {
	user, err := db.GetUserById(t.Context(), "1")
	require.NoError(t, err)

	assert.Equal(t, "adam", user.Name)
	assert.Equal(t, "adam@example.com", user.Email)
}

func runCreateUserTest(t *testing.T, db DB) {
	err := db.CreateUser(t.Context(), &User{"1", "adam", "adam@example.com"})
	require.NoError(t, err)

	user, err := db.GetUserById(t.Context(), "1")
	require.NoError(t, err)

	assert.Equal(t, user.Name, "adam")
	assert.Equal(t, user.Email, "adam@example.com")
}

func runUpdateUserTest(t *testing.T, db DB) {
	err := db.UpdateUser(t.Context(), &User{"1", "ally", "ally@example.com"})
	require.NoError(t, err)

	user, err := db.GetUserById(t.Context(), "1")
	require.NoError(t, err)

	assert.Equal(t, user.Name, "ally")
	assert.Equal(t, user.Email, "ally@example.com")
}
