package rbac

import (
	"fmt"
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var (
	userRoles map[User][]Role
	roleUsers map[Role][]User
)

func loadUsersAndRoles() {
	userRoles = make(map[User][]Role)
	roleUsers = make(map[Role][]User)
	for i := 0; i < 10; i++ {
		user := User(strconv.Itoa(i))
		role2 := Role("2_" + strconv.Itoa(i%2))
		role3 := Role("3_" + strconv.Itoa(i%3))
		role5 := Role("5_" + strconv.Itoa(i%5))

		userRoles[user] = []Role{role2, role3, role5}
		roleUsers[role2] = append(roleUsers[role2], user)
		roleUsers[role3] = append(roleUsers[role3], user)
		roleUsers[role5] = append(roleUsers[role5], user)
	}
}

var _ = Describe("grouping implementation", func() {
	Expect(userRoles).NotTo(BeEmpty())
	Expect(roleUsers).NotTo(BeEmpty())

	var (
		g Grouping
	)

	for _, tg := range []struct {
		name string
		ctor func() Grouping
	}{
		{
			name: "simple",
			ctor: func() Grouping { return newSimpleGrouping() },
		},
		{
			name: "fat",
			ctor: func() Grouping { return newFatGrouping(newSimpleGrouping()) },
		},
	} {
		BeforeEach(func() {
			g = tg.ctor()
		})

		Context(tg.name, func() {
			BeforeEach(func() {
				for user, roles := range userRoles {
					for _, role := range roles {
						Expect(g.Join(user, role)).Should(Succeed())
					}
				}
			})

			It("should contain initial users", func() {
				Expect(g.AllUsers()).Should(haveExactKeys(
					User("0"), User("1"), User("2"), User("3"), User("4"),
					User("5"), User("6"), User("7"), User("8"), User("9"),
				))
			})

			It("should contain initial roles", func() {
				Expect(g.AllRoles()).Should(haveExactKeys(
					Role("2_0"), Role("2_1"),
					Role("3_0"), Role("3_1"), Role("3_2"),
					Role("5_0"), Role("5_1"), Role("5_2"), Role("5_3"), Role("5_4"),
				))
			})

			Context("querying roles of user", func() {
				for user, roles := range userRoles {
					It(fmt.Sprintf("should know roles of %s", user.subject()), func() {
						Expect(g.RolesOf(user)).Should(haveExactKeys(func() []interface{} {
							is := make([]interface{}, 0, len(roles))
							for _, role := range roles {
								is = append(is, role)
							}
							return is
						}()...))
					})
				}
			})

			Context("querying users of role", func() {
				for role, users := range roleUsers {
					It(fmt.Sprintf("should know users of %s", role.subject()), func() {
						Expect(g.UsersOf(role)).Should(haveExactKeys(func() []interface{} {
							is := make([]interface{}, 0, len(users))
							for _, user := range users {
								is = append(is, user)
							}
							return is
						}()...))
					})
				}
			})

			Context("checking user-role relationships", func() {
				for user, roles := range userRoles {
					for _, role := range roles {
						user, role := user, role
						It(fmt.Sprintf("should know %s is in %s", user.subject(), role.subject()), func() {
							Expect(g.IsIn(user, role)).Should(BeTrue())
						})
					}
				}

				for _, tc := range []struct {
					user User
					role Role
				}{
					{user: User("1"), role: Role("2_0")},
					{user: User("4"), role: Role("3_0")},
					{user: User("4"), role: Role("3_2")},
					{user: User("6"), role: Role("2_1")},
					{user: User("6"), role: Role("3_1")},
					{user: User("6"), role: Role("3_2")},
				} {
					It(fmt.Sprintf("should know %s is not in %s", tc.user.subject(), tc.role.subject()), func() {
						Expect(g.IsIn(tc.user, tc.role)).Should(BeFalse())
					})
				}
			})

			Describe("removing user-role grouping", func() {
				BeforeEach(func() {
					Expect(g.Leave(User("1"), Role("3_1"))).Should(Succeed())
				})

				It("should remove the role from roles of the user", func() {
					Expect(g.RolesOf(User("1"))).ShouldNot(HaveKey(Role("3_1")))
				})

				It("should remove the user from users of the role", func() {
					Expect(g.UsersOf(Role("3_1"))).ShouldNot(HaveKey(User("1")))
				})

				It("should remove the user-role relationship", func() {
					Expect(g.IsIn(User("1"), Role("3_1"))).Should(BeFalse())
				})

				It("should not remove other user-role relationships", func() {
					Expect(g.IsIn(User("1"), Role("2_1"))).Should(BeTrue())
					Expect(g.IsIn(User("4"), Role("3_1"))).Should(BeTrue())
				})
			})

			Describe("removing role", func() {
				BeforeEach(func() {
					Expect(g.RemoveRole(Role("3_2"))).Should(Succeed())
				})

				It("should remove it from all roles", func() {
					Expect(g.AllRoles()).ShouldNot(HaveKey(Role("3_2")))
				})

				DescribeTable("should remove it from roles of its users",
					func(user User) {
						Expect(g.RolesOf(user)).ShouldNot(HaveKey(Role("3_2")))
					},
					Entry("user 2", User("2")),
					Entry("user 5", User("5")),
					Entry("user 8", User("8")),
				)

				DescribeTable("should remove relationships about it",
					func(user User) {
						Expect(g.IsIn(user, Role("3_2"))).Should(BeFalse())
					},
					Entry("user 2", User("2")),
					Entry("user 5", User("5")),
					Entry("user 8", User("8")),
				)
			})

			Describe("removing user", func() {
				BeforeEach(func() {
					Expect(g.RemoveUser(User("2"))).Should(Succeed())
				})

				It("should remove it from all users", func() {
					Expect(g.AllUsers()).ShouldNot(HaveKey(User("2")))
				})

				DescribeTable("should remove it from users of its roles",
					func(role Role) {
						Expect(g.UsersOf(role)).ShouldNot(HaveKey(User("2")))
					},
					Entry("role 2_0", Role("2_0")),
					Entry("role 3_2", Role("3_2")),
					Entry("role 5_2", Role("5_2")),
				)

				DescribeTable("should remove replationships about it",
					func(role Role) {
						Expect(g.IsIn(User("2"), role)).Should(BeFalse())
					},
					Entry("role 2_0", Role("2_0")),
					Entry("role 3_2", Role("3_2")),
					Entry("role 5_2", Role("5_2")),
				)
			})

			Describe("with role-to-role groupings", func() {
				BeforeEach(func() {
					for _, tc := range []struct {
						subRoles []Role
						role     Role
					}{
						{
							subRoles: []Role{Role("2_0"), Role("3_0")},
							role:     Role("6_0"),
						},

						{
							subRoles: []Role{Role("2_0"), Role("5_0")},
							role:     Role("10_0"),
						},
					} {
						for _, subRole := range tc.subRoles {
							Expect(g.Join(subRole, tc.role)).Should(Succeed())
						}
					}
				})

				DescribeTable("user belongs to role of its role",
					func(user User, role Role) {
						Expect(g.IsIn(user, role)).Should(BeTrue())
					},
					Entry("user 0", User("0"), Role("6_0")),
					Entry("user 6", User("6"), Role("6_0")),
					Entry("user 0", User("0"), Role("10_0")),
				)
			})
		})
	}
})
