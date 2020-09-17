package fake_test

import (
	"context"
	"testing"

	. "github.com/houz42/rbac/internal/persist/fake"
	. "github.com/houz42/rbac/persist/test"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestFakePersisters(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "fake persisters")
}

var _ = BeforeSuite(func() {
	ctx := context.Background()
	TestGroupingPersister(NewGroupingPersister())
	TestPermissionPersister(NewPermissionPersister(ctx))
})

var _ = Describe("mgo persisters", func() {
	_ = GroupingCases
	_ = PermissionCases
})
