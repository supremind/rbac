package rbac

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestGrouping(t *testing.T) {
	RegisterFailHandler(Fail)
	loadUsersAndRoles()
	RunSpecs(t, "user role grouping")
}

func haveKeys(keys ...interface{}) types.GomegaMatcher {
	return &haveKeysMatcher{
		keys: keys,
	}
}

type haveKeysMatcher struct {
	keys []interface{}
}

func (m *haveKeysMatcher) Match(actual interface{}) (success bool, err error) {
	switch reflect.TypeOf(actual).Kind() {
	case reflect.Map:
	default:
		return false, fmt.Errorf("haveKeysMatcher expects a map")
	}

	for _, key := range m.keys {
		match, e := HaveKey(key).Match(actual)
		if e != nil {
			return false, e
		}
		if !match {
			return false, nil
		}
	}

	return true, nil
}

func (m *haveKeysMatcher) FailureMessage(actual interface{}) (message string) {
	return format.Message(actual, "to have keys", m.keys)
}

func (m *haveKeysMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return format.Message(actual, "not to have keys", m.keys)
}

func haveExactKeys(keys ...interface{}) types.GomegaMatcher {
	return &haveExactKeysMatcher{
		keys: keys,
	}
}

type haveExactKeysMatcher struct {
	keys []interface{}
}

func (m *haveExactKeysMatcher) Match(actual interface{}) (success bool, err error) {
	switch reflect.TypeOf(actual).Kind() {
	case reflect.Map:
	default:
		return false, fmt.Errorf("haveExactKeysMatcher expects a map")
	}

	if reflect.ValueOf(actual).Len() != len(m.keys) {
		return false, fmt.Errorf("expect %d keys, got %d", len(m.keys), reflect.ValueOf(actual).Len())
	}

	return haveKeys(m.keys...).Match(actual)
}

func (m *haveExactKeysMatcher) FailureMessage(actual interface{}) (message string) {
	return format.Message(actual, "to have exact keys", m.keys)
}

func (m *haveExactKeysMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return format.Message(actual, "not to have exact keys", m.keys)
}
