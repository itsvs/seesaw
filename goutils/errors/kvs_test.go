package errors_test

import (
	"testing"

	"github.com/itsvs/seesaw/goutils/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKvError(t *testing.T) {
	t.Run("single error with kvs", func(t *testing.T) {
		err := errors.New("my error", errors.Kv("one", "hi"), errors.Kv("two", true))
		require.Error(t, err)

		kvs := errors.Kvs(err)
		assert.NotNil(t, kvs)
		assert.Equal(t, kvs["one"].(string), "hi")
		assert.True(t, kvs["two"].(bool))
		assert.Equal(t, "my error", err.Error())
	})

	t.Run("wrapped error with kvs", func(t *testing.T) {
		err := errors.New("my error", errors.Kv("one", "hi"), errors.Kv("two", true))
		require.Error(t, err)

		err = errors.Wrap(err, "my wrapper", errors.Kv("two", false), errors.Kv("three", 21))

		kvs := errors.Kvs(err)
		assert.NotNil(t, kvs)
		assert.Equal(t, "hi", kvs["one"].(string))
		assert.False(t, kvs["two"].(bool))
		assert.Equal(t, 21, kvs["three"].(int))
		assert.Equal(t, "my wrapper: my error", err.Error())
	})
}
