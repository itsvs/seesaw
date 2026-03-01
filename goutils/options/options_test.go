package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreatePerson(t *testing.T) {
	t.Run("no options", func(t *testing.T) {
		p := CreatePerson()
		assert.Empty(t, p.Name)
		assert.Empty(t, p.Emails)
	})

	t.Run("name provided", func(t *testing.T) {
		p := CreatePerson(WithName("Chandler Bing"))
		assert.Equal(t, "Chandler Bing", p.Name)
		assert.Empty(t, p.Emails)
	})

	t.Run("name and emails provided", func(t *testing.T) {
		p := CreatePerson(WithName("Chandler Bing"), WithEmail("chandler@friends.com"), WithEmail("chanandler@friends.com"))
		assert.Equal(t, "Chandler Bing", p.Name)
		assert.ElementsMatch(t, []string{"chandler@friends.com", "chanandler@friends.com"}, p.Emails)
	})
}
