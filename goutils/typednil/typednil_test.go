package typednil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPerson(t *testing.T) {
	t.Run("nil person", func(t *testing.T) {
		var p *Person
		assert.Equal(t, "", p.GetName())
		assert.Empty(t, p.GetFriends())

		err := p.AddFriend(nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilPerson)
	})

	t.Run("non-nil person", func(t *testing.T) {
		p := NewPerson("phineas")
		assert.Equal(t, "phineas", p.GetName())
		assert.Empty(t, p.GetFriends())

		err := p.AddFriend(nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilPerson)

		err = p.AddFriend(NewPerson("baljeet"))
		require.NoError(t, err)

		friends := p.GetFriends()
		assert.Len(t, friends, 1)
		assert.Equal(t, "baljeet", friends[0].GetName())
	})
}
