package test

import (
	"context"

	"github.com/houz42/rbac/types"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var gp types.GroupingPersister

func TestGroupingPersister(p types.GroupingPersister) {
	gp = p
}

var GroupingCases = Describe("grouping persister", func() {
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

	It("insert and remove policies as expected", func() {
		policy := insertPolices[0]
		Expect(gp.Insert(policy.Entity, policy.Group)).To(Succeed())
		Expect(gp.Insert(policy.Entity, policy.Group)).NotTo(Succeed())

		Expect(gp.Remove(policy.Entity, policy.Group)).To(Succeed())
		Expect(gp.Remove(policy.Entity, policy.Group)).NotTo(Succeed())
	})

	It("gen and receive change events", func() {
		w, e := gp.Watch(context.Background())
		Expect(e).To(Succeed())

		go func() {
			defer GinkgoRecover()

			for _, policy := range insertPolices {
				Expect(gp.Insert(policy.Entity, policy.Group)).To(Succeed())
			}
			for _, policy := range removePolices {
				Expect(gp.Remove(policy.Entity, policy.Group)).To(Succeed())
			}
		}()

		for _, change := range changes {
			got, ok := <-w
			Expect(ok).To(BeTrue())
			Expect(got).To(Equal(change))
		}

		Consistently(w).ShouldNot(Receive())

		Expect(gp.List()).To(ConsistOf(insertPolices[0], insertPolices[2], insertPolices[4]))
	})
})
