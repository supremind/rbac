package test

import (
	"context"

	"github.com/houz42/rbac/types"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func GroupingPersisterTestCases(ctx context.Context, name string, gp types.GroupingPersister) bool {
	insertPolices := []types.GroupingPolicy{
		{Entity: types.User("alan"), Group: types.Role("a")},
		{Entity: types.User("albert"), Group: types.Role("a")},
		{Entity: types.User("edison"), Group: types.Role("e")},
		{Entity: types.User("eve"), Group: types.Role("e")},
		{Entity: types.User("issac"), Group: types.Role("i")},
	}
	removePolices := []types.GroupingPolicy{
		{Entity: types.User("albert"), Group: types.Role("a")},
		{Entity: types.User("eve"), Group: types.Role("e")},
	}

	changes := make([]types.GroupingPolicyChange, 0, len(insertPolices)+len(removePolices))
	for _, policy := range insertPolices {
		changes = append(changes, types.GroupingPolicyChange{
			GroupingPolicy: policy,
			Method:         types.PersistInsert,
		})
	}
	for _, policy := range removePolices {
		changes = append(changes, types.GroupingPolicyChange{
			GroupingPolicy: policy,
			Method:         types.PersistDelete,
		})
	}

	return Describe(name, func() {
		It("send and receive changes", func() {
			go func() {
				defer GinkgoRecover()

				for _, policy := range insertPolices {
					Expect(gp.Insert(policy.Entity, policy.Group)).To(Succeed())
				}

				for _, policy := range removePolices {
					Expect(gp.Remove(policy.Entity, policy.Group)).To(Succeed())
				}
			}()

			w, e := gp.Watch(ctx)
			Expect(e).To(Succeed())

			for _, change := range changes {
				Expect(<-w).To(Equal(change))
			}

			Consistently(w).ShouldNot(Receive())
		})

		It("should list all remaining polices", func() {
			Expect(gp.List()).To(ConsistOf(insertPolices[0], insertPolices[2], insertPolices[4]))
		})
	})
}
