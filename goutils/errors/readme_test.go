package errors_test

import (
	"fmt"
	"testing"

	"github.com/itsvs/seesaw/goutils/errors"
	"github.com/stretchr/testify/assert"
)

func TestReadme(t *testing.T) {
	t.Run("wrapped without kvs", func(t *testing.T) {
		// GetStaffMemberByPosiiton("eladta")
		err := errors.New(fmt.Sprintf("invalid position %s", "eladta"))
		// GetCourseLead("cs101")
		err = errors.Wrap(err, fmt.Sprintf("couldn't get %s course lead", "cs101"))
		// GetDepartmentLeads("compsci")
		err = errors.Wrap(err, fmt.Sprintf("couldn't get %s dept leads", "compsci"))

		assert.Equal(t, "couldn't get compsci dept leads: couldn't get cs101 course lead: invalid position eladta", err.Error())
	})

	t.Run("wrapped with kvs", func(t *testing.T) {
		// GetStaffMemberByPosiiton("eladta")
		err := errors.New("invalid position", errors.Kv("position", "eladta"))
		// GetCourseLead("cs101")
		err = errors.Wrap(err, "couldn't get course lead", errors.Kv("course", "cs101"))
		// GetDepartmentLeads("compsci")
		err = errors.Wrap(err, "couldn't get dept leads", errors.Kv("dept", "compsci"))

		assert.Equal(t, "couldn't get dept leads: couldn't get course lead: invalid position", err.Error())
		assert.Equal(t, "compsci", errors.Kvs(err)["dept"])
		assert.Equal(t, "cs101", errors.Kvs(err)["course"])
		assert.Equal(t, "eladta", errors.Kvs(err)["position"])
	})
}
