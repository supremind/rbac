package grouping

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	. "github.com/supremind/rbac/internal/testdata"
	"github.com/supremind/rbac/types"
)

var _ = Describe("fat grouping", func() {
	Specify("init grouping polices are created", func() {
		Expect(UserRoles).NotTo(BeEmpty())
		Expect(RoleUsers).NotTo(BeEmpty())
	})

	g := newFatGrouping()

	JustAfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			fmt.Printf("Collecting diags just after failed test in %s\n", CurrentGinkgoTestDescription().TestText)
			fmt.Printf("[member => group] %v\n", g.memberGroups)
			fmt.Printf("[group => member] %v\n", g.groupMembers)
			fmt.Printf("[group to upper] %v\n", g.groupUpward)
			fmt.Printf("[group to lower] %v\n", g.groupDownward)
		}
	})

	When("users joined init roles", func() {
		BeforeEach(func() {
			for user, roles := range UserRoles {
				for _, role := range roles {
					Expect(g.Join(user, role)).To(Succeed())

					Expect(g.AllGroups()).To(HaveKey(role))
					Expect(g.AllMembers()).To(HaveKey(user))
					Expect(g.groupMembers).To(HaveKey(role))
					Expect(g.groupMembers[role]).To(HaveKey(user))
					Expect(g.memberGroups).To(HaveKey(user))
					Expect(g.memberGroups[user]).To(HaveKey(role))
				}
			}
		})

		It("should contain all users", func() {
			users := func() []interface{} {
				res := make([]interface{}, 0, len(UserRoles))
				for user := range UserRoles {
					res = append(res, user)
				}
				return res
			}()
			Expect(g.AllMembers()).To(haveExactKeys(users...))
			Expect(g.memberGroups).To(haveExactKeys(users...))
		})

		It("knows roles of every user", func() {
			for user, roles := range UserRoles {
				Expect(g.memberGroups).To(HaveKey(user))
				Expect(g.memberGroups[user]).To(haveExactKeys(func() []interface{} {
					res := make([]interface{}, 0, len(roles))
					for _, role := range roles {
						res = append(res, role)
					}
					return res
				}()...))
			}
		})

		It("should contain all roles", func() {
			roles := func() []interface{} {
				res := make([]interface{}, 0, len(RoleUsers))
				for role := range RoleUsers {
					res = append(res, role)
				}
				return res
			}()
			Expect(g.AllGroups()).To(haveExactKeys(roles...))
			Expect(g.groupMembers).To(haveExactKeys(roles...))
		})

		It("knows users of every role", func() {
			for role, users := range RoleUsers {
				Expect(g.groupMembers).To(HaveKey(role))
				Expect(g.groupMembers[role]).To(haveExactKeys(func() []interface{} {
					res := make([]interface{}, 0, len(users))
					for _, user := range users {
						res = append(res, user)
					}
					return res
				}()...))
			}
		})

		Context("with role-to-role relationships", func() {
			BeforeEach(func() {
				for sub, roles := range RoleInRoles {
					for _, role := range roles {
						Expect(g.Join(sub, role)).To(Succeed())

						Expect(g.AllGroups()).To(HaveKey(role))
						Expect(g.AllGroups()).To(HaveKey(sub))
					}
				}
			})

			DescribeTable("knows indirect roles of users",
				func(user types.User, role types.Role) {
					Expect(g.IsIn(user, role)).To(BeTrue())
					Expect(g.memberGroups).To(HaveKey(user))
					Expect(g.memberGroups[user]).To(HaveKey(role))
					Expect(g.groupMembers).To(HaveKey(role))
					Expect(g.groupMembers[role]).To(HaveKey(user))
				},
				Entry("2 is even", types.User("2"), types.Role("even")),
				Entry("2 is divisible", types.User("2"), types.Role("divisible")),
				Entry("3 is divisible", types.User("3"), types.Role("divisible")),
				Entry("4 is even", types.User("4"), types.Role("even")),
				Entry("4 is divisible", types.User("4"), types.Role("divisible")),
				Entry("5 is divisible", types.User("5"), types.Role("divisible")),
				Entry("6 is even", types.User("6"), types.Role("even")),
				Entry("6 is divisible", types.User("6"), types.Role("divisible")),
			)

			When("one role is removed", func() {
				BeforeEach(func() {
					Expect(g.RemoveGroup(types.Role("even"))).To(Succeed())
					Expect(g.AllGroups()).ToNot(HaveKey(types.Role("even")))
				})

				DescribeTable("does not know indirect role of effected users",
					func(user types.User, role types.Role) {
						Expect(g.IsIn(user, role)).To(BeFalse())
					},
					Entry("2 is even", types.User("2"), types.Role("even")),
					Entry("2 is divisible", types.User("2"), types.Role("divisible")),
					Entry("4 is even", types.User("4"), types.Role("even")),
					Entry("4 is divisible", types.User("4"), types.Role("divisible")),
					Entry("6 is even", types.User("6"), types.Role("even")),
				)
			})

			When("one user is removed", func() {
				BeforeEach(func() {
					Expect(g.RemoveMember(types.User("2"))).To(Succeed())
					Expect(g.AllMembers()).NotTo(HaveKey(types.User("2")))
					Expect(g.memberGroups).NotTo(HaveKey(types.User("2")))
				})

				DescribeTable("does not know roles of removed user",
					func(role types.Role) {
						Expect(g.IsIn(types.User("2"), role)).To(BeFalse())
					},
					Entry("2 is even", types.Role("even")),
					Entry("2 is divisible", types.Role("divisible")),
					Entry("2 is 2_0", types.Role("2_0")),
					Entry("2 is 3_2", types.Role("3_2")),
					Entry("2 is 5_2", types.Role("5_2")),
				)
			})

			When("role-to-role relationships are removed", func() {
				BeforeEach(func() {
					for sub, roles := range RoleInRoles {
						for _, role := range roles {
							Expect(g.Leave(sub, role)).To(Succeed())
						}
					}
				})

				DescribeTable("does not know indirect roles of users",
					func(user types.User, role types.Role) {
						Expect(g.IsIn(user, role)).To(BeFalse())
					},
					Entry("2 is even", types.User("2"), types.Role("even")),
					Entry("2 is divisible", types.User("2"), types.Role("divisible")),
					Entry("3 is divisible", types.User("3"), types.Role("divisible")),
					Entry("4 is even", types.User("4"), types.Role("even")),
					Entry("4 is divisible", types.User("4"), types.Role("divisible")),
					Entry("5 is divisible", types.User("5"), types.Role("divisible")),
					Entry("6 is even", types.User("6"), types.Role("even")),
					Entry("6 is divisible", types.User("6"), types.Role("divisible")),
				)
			})
		})

		It("should leave users from roles", func() {
			for user, roles := range UserRoles {
				for _, role := range roles {
					Expect(g.Leave(user, role)).To(Succeed())
					Expect(g.groupMembers).To(HaveKey(role))
					Expect(g.groupMembers[role]).NotTo(HaveKey(user))
					Expect(g.memberGroups).To(HaveKey(user))
					Expect(g.memberGroups[user]).NotTo(HaveKey(role))
				}
			}
		})
	})
})
