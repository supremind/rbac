package test

import (
	"context"
	"fmt"

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

	It("should do grouping policy curd", func() {
		By("insert and remove single policy only once")
		policy := insertPolices[0]
		Expect(gp.Insert(policy.Entity, policy.Group)).To(Succeed())
		Expect(gp.Insert(policy.Entity, policy.Group)).NotTo(Succeed())

		Expect(gp.Remove(policy.Entity, policy.Group)).To(Succeed())
		Expect(gp.Remove(policy.Entity, policy.Group)).NotTo(Succeed())

		By("start watching grouping policy changes")
		w, e := gp.Watch(context.Background())
		Expect(e).To(Succeed())

		go func() {
			defer GinkgoRecover()

			for _, policy := range insertPolices {
				By(fmt.Sprintf("insert %v", policy))
				Expect(gp.Insert(policy.Entity, policy.Group)).To(Succeed())
			}
			for _, policy := range removePolices {
				By(fmt.Sprintf("remove %v", policy))
				Expect(gp.Remove(policy.Entity, policy.Group)).To(Succeed())
			}

		}()

		By("observe changes in sequence")
		for _, change := range changes {
			By(fmt.Sprintf("should observe %v", change))
			got, ok := <-w
			Expect(ok).To(BeTrue())
			Expect(got).To(Equal(change))
		}

		By("after that, should bot observe any changes more")
		Consistently(w).ShouldNot(Receive())

		By("list all polices remained")
		Expect(gp.List()).To(ConsistOf(insertPolices[0], insertPolices[2], insertPolices[4]))

	})
})
