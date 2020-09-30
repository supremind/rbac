package test

import (
	"context"
	"fmt"

	"github.com/houz42/rbac/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var pp types.PermissionPersister

func TestPermissionPersister(p types.PermissionPersister) {
	pp = p
}

var PermissionCases = Describe("permission persister", func() {
	insertPolices := []types.PermissionPolicy{
		{Subject: types.User("alan"), Object: types.Article("project apollo"), Action: types.ReadWrite},
		{Subject: types.User("alan"), Object: types.Article("manhattan project"), Action: types.Read},
		{Subject: types.User("karman"), Object: types.Category("war"), Action: types.ReadWrite},
		{Subject: types.Role("european"), Object: types.Category("europe"), Action: types.Read},
		{Subject: types.Role("european"), Object: types.Article("opeartion markert garden"), Action: types.Exec},
	}
	updatePolices := []types.PermissionPolicy{
		{Subject: types.Role("european"), Object: types.Category("europe"), Action: types.ReadWrite},
		{Subject: types.User("karman"), Object: types.Category("war"), Action: types.Read},
	}
	removePolices := []types.PermissionPolicy{
		{Subject: types.User("karman"), Object: types.Category("war")},
	}

	changes := make([]types.PermissionPolicyChange, 0, len(insertPolices)+len(updatePolices)+len(removePolices))
	for _, policy := range insertPolices {
		changes = append(changes, types.PermissionPolicyChange{
			PermissionPolicy: policy,
			Method:           types.PersistInsert,
		})
	}
	for _, policy := range updatePolices {
		changes = append(changes, types.PermissionPolicyChange{
			PermissionPolicy: policy,
			Method:           types.PersistUpdate,
		})
	}
	for _, policy := range removePolices {
		changes = append(changes, types.PermissionPolicyChange{
			PermissionPolicy: policy,
			Method:           types.PersistDelete,
		})
	}

	It("should do permission policy crud", func() {
		By("insert and remvoe single policy as expected")
		policy := insertPolices[0]
		Expect(pp.Insert(policy.Subject, policy.Object, policy.Action)).To(Succeed())
		Expect(pp.Insert(policy.Subject, policy.Object, policy.Action)).NotTo(Succeed())

		Expect(pp.Remove(policy.Subject, policy.Object)).To(Succeed())
		Expect(pp.Remove(policy.Subject, policy.Object)).NotTo(Succeed())

		By("start watching permission changes")
		w, e := pp.Watch(context.Background())
		Expect(e).To(Succeed())

		go func() {
			defer GinkgoRecover()

			By("insert, update, remove polices")
			for _, policy := range insertPolices {
				By(fmt.Sprintf("insert %v", policy))
				Expect(pp.Insert(policy.Subject, policy.Object, policy.Action)).To(Succeed())
			}

			for _, policy := range updatePolices {
				By(fmt.Sprintf("update %v", policy))
				Expect(pp.Update(policy.Subject, policy.Object, policy.Action)).To(Succeed())
			}

			for _, policy := range removePolices {
				By(fmt.Sprintf("remove %v", policy))
				Expect(pp.Remove(policy.Subject, policy.Object)).To(Succeed())
			}
		}()

		By("observe changes in sequence")
		for _, change := range changes {
			By(fmt.Sprintf("should observe %v", change))
			got, ok := <-w
			Expect(ok).To(BeTrue())
			Expect(got).To(Equal(change))
		}

		By("after that, should not observe any change more")
		Consistently(w).ShouldNot(Receive())

		By("list all policies remained")
		Expect(pp.List()).To(ConsistOf(
			types.PermissionPolicy{Subject: types.User("alan"), Object: types.Article("project apollo"), Action: types.ReadWrite},
			types.PermissionPolicy{Subject: types.User("alan"), Object: types.Article("manhattan project"), Action: types.Read},
			types.PermissionPolicy{Subject: types.Role("european"), Object: types.Category("europe"), Action: types.ReadWrite},
			types.PermissionPolicy{Subject: types.Role("european"), Object: types.Article("opeartion markert garden"), Action: types.Exec},
		))
	})

})
