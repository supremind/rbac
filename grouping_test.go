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

var objectGroupings = []struct {
	art Article
	cat Category
}{
	{art: Article("project apollo"), cat: Category("peace")},
	{art: Article("manhattan project"), cat: Category("war")},
	{art: Article("operation market garden"), cat: Category("war")},
	{art: Article("operation overlord"), cat: Category("war")},

	{art: Article("project apollo"), cat: Category("america")},
	{art: Article("manhattan project"), cat: Category("america")},
	{art: Article("operation market garden"), cat: Category("europe")},
	{art: Article("operation overlord"), cat: Category("europe")},

	{art: Article("project apollo"), cat: Category("success")},
	{art: Article("manhattan project"), cat: Category("success")},
	{art: Article("operation market garden"), cat: Category("success")},
	{art: Article("operation overlord"), cat: Category("fail")},
}

var _ = Describe("grouper implementation", func() {
	Expect(userRoles).NotTo(BeEmpty())
	Expect(roleUsers).NotTo(BeEmpty())

	var groupers = []struct {
		name string
		g    Grouping
	}{
		{
			name: "slim",
			g:    newSlimGrouping(),
		},
		{
			name: "fat",
			g:    newFatGrouping(),
		},
		{
			name: "synced fat",
			g:    newSyncedGrouping(newFatGrouping()),
		},
		{
			name: "synced slim",
			g:    newSyncedGrouping(newSlimGrouping()),
		},
	}

	for _, tg := range groupers {
		Context(tg.name, func() {
			g := tg.g

			BeforeEach(func() {
				for user, roles := range userRoles {
					for _, role := range roles {
						Expect(g.Join(user, role)).To(Succeed())
					}
				}
			})

			It("should contain initial users", func() {
				Expect(g.AllIndividuals()).To(haveExactKeys(
					User("0"), User("1"), User("2"), User("3"), User("4"),
					User("5"), User("6"), User("7"), User("8"), User("9"),
				))
			})

			It("should contain initial roles", func() {
				Expect(g.AllGroups()).To(haveExactKeys(
					Role("2_0"), Role("2_1"),
					Role("3_0"), Role("3_1"), Role("3_2"),
					Role("5_0"), Role("5_1"), Role("5_2"), Role("5_3"), Role("5_4"),
				))
			})

			Context("querying roles of user", func() {
				for user, roles := range userRoles {
					It(fmt.Sprintf("should know roles of %s", user), func() {
						Expect(g.GroupsOf(user)).To(haveExactKeys(func() []interface{} {
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
					It(fmt.Sprintf("should know users of %s", role), func() {
						Expect(g.IndividualsIn(role)).To(haveExactKeys(func() []interface{} {
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
						It(fmt.Sprintf("should know %s is in %s", user, role), func() {
							Expect(g.IsIn(user, role)).To(BeTrue())
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
					It(fmt.Sprintf("should know %s is not in %s", tc.user, tc.role), func() {
						Expect(g.IsIn(tc.user, tc.role)).To(BeFalse())
					})
				}
			})

			DescribeTable("user leaves role",
				func(user User, role Role) {
					Expect(g.Leave(user, role)).To(Succeed())
					Expect(g.GroupsOf(user)).NotTo(HaveKey(role), fmt.Sprintf("%s should not be in roles of %s", role, user))
					Expect(g.IndividualsIn(role)).NotTo(HaveKey(user), fmt.Sprintf("%s should not be in users of %s", user, role))
					Expect(g.IsIn(user, role)).NotTo(BeTrue(), fmt.Sprintf("%s should not be in %s", user, role))
				},
				Entry("user 1 leaves role 3_1", User("1"), Role("3_1")),
				Entry("user 7 leaves role 5_2", User("7"), Role("5_2")),
				Entry("user 6 leaves role 3_0", User("6"), Role("3_0")),
			)

			Describe("removing role", func() {
				BeforeEach(func() {
					Expect(g.RemoveGroup(Role("3_2"))).To(Succeed())
				})

				It("should remove it from all roles", func() {
					Expect(g.AllGroups()).NotTo(HaveKey(Role("3_2")))
				})

				DescribeTable("should remove it from roles of its users",
					func(user User) {
						Expect(g.GroupsOf(user)).NotTo(HaveKey(Role("3_2")))
					},
					Entry("user 2", User("2")),
					Entry("user 5", User("5")),
					Entry("user 8", User("8")),
				)

				DescribeTable("users should not be in it anymore",
					func(user User) {
						Expect(g.IsIn(user, Role("3_2"))).NotTo(BeTrue())
					},
					Entry("user 2", User("2")),
					Entry("user 5", User("5")),
					Entry("user 8", User("8")),
				)
			})

			Describe("removing user", func() {
				BeforeEach(func() {
					Expect(g.RemoveIndividual(User("2"))).To(Succeed())
				})

				It("should remove it from all users", func() {
					Expect(g.AllIndividuals()).NotTo(HaveKey(User("2")))
				})

				DescribeTable("should remove it from users of its roles",
					func(role Role) {
						Expect(g.IndividualsIn(role)).NotTo(HaveKey(User("2")))
					},
					Entry("role 2_0", Role("2_0")),
					Entry("role 3_2", Role("3_2")),
					Entry("role 5_2", Role("5_2")),
				)

				DescribeTable("should remove relationships about it",
					func(role Role) {
						Expect(g.IsIn(User("2"), role)).To(BeFalse())
					},
					Entry("role 2_0", Role("2_0")),
					Entry("role 3_2", Role("3_2")),
					Entry("role 5_2", Role("5_2")),
				)
			})

			Describe("with role-to-role groupings", func() {
				BeforeEach(func() {
					Expect(g.Join(Role("2_0"), Role("even"))).To(Succeed())
					Expect(g.Join(Role("2_0"), Role("divisible"))).To(Succeed())
					Expect(g.Join(Role("3_0"), Role("divisible"))).To(Succeed())
					Expect(g.Join(Role("5_0"), Role("divisible"))).To(Succeed())
				})

				DescribeTable("querying direct subjects of role",
					func(role Role, subjects []interface{}) {
						Expect(g.ImmediateEntitiesIn(role)).To(haveExactKeys(subjects...))
					},
					Entry("users of role 3_0", Role("3_0"), []interface{}{User("0"), User("3"), User("6"), User("9")}),
					Entry("sub roles of divisible", Role("divisible"), []interface{}{Role("2_0"), Role("3_0"), Role("5_0")}),
				)

				DescribeTable("querying direct roles of subject",
					func(sub Subject, roles []interface{}) {
						Expect(g.ImmediateGroupsOf(sub)).To(haveExactKeys(roles...))
					},
					Entry("roles of user 9", User("9"), []interface{}{Role("2_1"), Role("3_0"), Role("5_4")}),
				)

				DescribeTable("querying users of super role",
					func(role Role, users []interface{}) {
						Expect(g.IndividualsIn(role)).To(haveExactKeys(users...))
					},
					Entry("even numbers", Role("even"), []interface{}{User("0"), User("2"), User("4"), User("6"), User("8")}),
					Entry("divisible numbers", Role("divisible"),
						[]interface{}{User("0"), User("2"), User("3"), User("4"), User("5"), User("6"), User("8"), User("9")},
					),
				)

				DescribeTable("querying roles of user",
					func(user User, roles []interface{}) {
						Expect(g.GroupsOf(user)).To(haveExactKeys(roles...))
					},
					Entry("roles of user 1", User("1"), []interface{}{Role("2_1"), Role("3_1"), Role("5_1")}),
					Entry("roles of user 4", User("4"), []interface{}{Role("2_0"), Role("3_1"), Role("5_4"), Role("even"), Role("divisible")}),
					Entry("roles of user 9", User("9"), []interface{}{Role("2_1"), Role("3_0"), Role("5_4"), Role("divisible")}),
				)

				Context("even numbers", func() {
					for _, u := range []int{0, 2, 4, 6, 8} {
						user := User(strconv.Itoa(u))
						Specify(fmt.Sprintf("%d is even", u), func() {
							Expect(g.IsIn(user, Role("even"))).To(BeTrue())
						})
					}
				})

				Context("divisible numbers", func() {
					for _, u := range []int{0, 2, 3, 4, 5, 6, 8, 9} {
						user := User(strconv.Itoa(u))
						Specify(fmt.Sprintf("%d is divisible", u), func() {
							Expect(g.IsIn(user, Role("divisible"))).To(BeTrue())
						})
					}
				})

				Context("indivisible numbers", func() {
					for _, u := range []int{1, 7} {
						user := User(strconv.Itoa(u))
						Specify(fmt.Sprintf("%d is not divisible", u), func() {
							Expect(g.IsIn(user, Role("divisible"))).To(BeFalse())
						})
					}
				})
			})
		})
	}
})
