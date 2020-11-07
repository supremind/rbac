package fake_test

import (
	"testing"

	. "github.com/supremind/rbac/persist/fake"
	. "github.com/supremind/rbac/persist/test"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestFakePersisters(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "fake persisters")
}

var _ = BeforeSuite(func() {
	TestGroupingPersister(NewGroupingPersister())
	TestPermissionPersister(NewPermissionPersister())
})

var _ = Describe("fake persisters", func() {
	_ = GroupingCases
	_ = PermissionCases
})
