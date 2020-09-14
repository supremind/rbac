package fake_test

import (
	"context"
	"testing"

	. "github.com/houz42/rbac/internal/persist/fake"
	. "github.com/houz42/rbac/persist/test"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestAction(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "fake persisters")
}

var ctx = context.Background()

var _ = GroupingPersisterTestCases(ctx, "fake grouping persister", NewGroupingPersister(ctx))

var _ = PermissionPersisterTestCases(ctx, "fake permission persister", NewPermissionPersister(ctx))
