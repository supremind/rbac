package test

import (
	"context"

	"github.com/houz42/rbac/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func PermissionPersisterTestCases(ctx context.Context, name string, pp types.PermissionPersister) bool {
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

	return Describe(name, func() {
		It("should send and receive changes", func() {
			go func() {
				defer GinkgoRecover()

				for _, policy := range insertPolices {
					Expect(pp.Insert(policy.Subject, policy.Object, policy.Action)).To(Succeed())
				}

				for _, policy := range updatePolices {
					Expect(pp.Update(policy.Subject, policy.Object, policy.Action)).To(Succeed())
				}

				for _, policy := range removePolices {
					Expect(pp.Remove(policy.Subject, policy.Object)).To(Succeed())
				}
			}()

			w, e := pp.Watch(ctx)
			Expect(e).To(Succeed())

			for _, change := range changes {
				Expect(<-w).To(Equal(change))
			}

			Consistently(w).ShouldNot(Receive())
		})

		It("should list all remaining polices", func() {
			Expect(pp.List()).To(ConsistOf(
				types.PermissionPolicy{Subject: types.User("alan"), Object: types.Article("project apollo"), Action: types.ReadWrite},
				types.PermissionPolicy{Subject: types.User("alan"), Object: types.Article("manhattan project"), Action: types.Read},
				types.PermissionPolicy{Subject: types.Role("european"), Object: types.Category("europe"), Action: types.ReadWrite},
				types.PermissionPolicy{Subject: types.Role("european"), Object: types.Article("opeartion markert garden"), Action: types.Exec},
			))
		})
	})
}
