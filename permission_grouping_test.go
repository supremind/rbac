package rbac

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var userToArticlePolices = []struct {
	sub User
	obj Article
	act Action
}{}

var userToCategoryPolices = []struct {
	sub User
	obj Category
	act Action
}{
	{sub: User("0"), obj: Category("war"), act: Read},
	{sub: User("0"), obj: Category("peace"), act: ReadWrite},
	{sub: User("0"), obj: Category("fail"), act: Read},
	{sub: User("1"), obj: Category("europe"), act: ReadExec},
	{sub: User("2"), obj: Category("fail"), act: ReadWrite},
	{sub: User("3"), obj: Category("war"), act: ReadExec},
}

var roleToArticlePolices = []struct {
	sub Role
	obj Article
	act Action
}{
	{sub: Role("2_0"), obj: Article("project apollo"), act: Read},
	{sub: Role("2_1"), obj: Article("project apollo"), act: ReadWriteExec},
	{sub: Role("3_0"), obj: Article("manhattan project"), act: Read},
	{sub: Role("3_1"), obj: Article("manhattan project"), act: ReadWrite},
	{sub: Role("3_2"), obj: Article("manhattan project"), act: ReadExec},
}

var roleToCategoryPolices = []struct {
	sub Role
	obj Category
	act Action
}{
	{sub: Role("2_0"), obj: Category("europe"), act: Read},
	{sub: Role("2_1"), obj: Category("europe"), act: ReadWriteExec},
	{sub: Role("3_0"), obj: Category("war"), act: Read},
	{sub: Role("3_1"), obj: Category("war"), act: ReadWrite},
	{sub: Role("3_2"), obj: Category("war"), act: ReadExec},
}

func loadRoleToArticlePolices(p Permission) {
	for _, perm := range roleToArticlePolices {
		perm := perm
		Expect(p.Permit(perm.sub, perm.obj, perm.act)).To(Succeed())
	}
}

func loadUserToCategoryPolices(p Permission) {
	for _, perm := range userToCategoryPolices {
		perm := perm
		Expect(p.Permit(perm.sub, perm.obj, perm.act)).To(Succeed())
	}
}

func loadRoleToCategoryPolices(p Permission) {
	for _, perm := range roleToCategoryPolices {
		perm := perm
		Expect(p.Permit(perm.sub, perm.obj, perm.act)).To(Succeed())
	}
}

func loadUserToArticlePolices(p Permission) {
	for _, perm := range userToArticlePolices {
		perm := perm
		Expect(p.Permit(perm.sub, perm.obj, perm.act)).To(Succeed())
	}
}

func newTestSubjectGrouping() Grouping {
	g := newFatGrouping()
	for user, roles := range userRoles {
		for _, role := range roles {
			Expect(g.Join(user, role)).To(Succeed())
		}
	}
	return g
}

func newTestObjectGrouping() Grouping {
	g := newFatGrouping()
	for _, tc := range objectGroupings {
		Expect(g.Join(tc.art, tc.cat)).To(Succeed())
	}
	return g
}

var subjectGroupedPermissions = []struct {
	name string
	ctor func() Permission
}{
	{
		name: "subject grouped",
		ctor: func() Permission {
			p := newSubjectGroupedPermission(newTestSubjectGrouping(), newThinPermission())
			loadRoleToArticlePolices(p)
			return p
		},
	},
	{
		name: "both grouped",
		ctor: func() Permission {
			p := newBothGroupedPermission(newTestSubjectGrouping(), newTestObjectGrouping(), newThinPermission())
			loadRoleToArticlePolices(p)
			return p
		},
	},
	{
		name: "subject grouped decision maker",
		ctor: func() Permission {
			p := newDecisionMaker(newTestSubjectGrouping(), nil, newThinPermission())
			loadRoleToArticlePolices(p)
			return p
		},
	},
}

var objectGroupedPermissions = []struct {
	name string
	ctor func() Permission
}{
	{
		name: "object grouped",
		ctor: func() Permission {
			p := newObjectGroupedPermission(newTestObjectGrouping(), newThinPermission())
			loadUserToCategoryPolices(p)
			return p
		},
	},
	{
		name: "both grouped",
		ctor: func() Permission {
			p := newBothGroupedPermission(newTestSubjectGrouping(), newTestObjectGrouping(), newThinPermission())
			loadUserToCategoryPolices(p)
			return p
		},
	},
	{
		name: "object grouped decision maker",
		ctor: func() Permission {
			p := newDecisionMaker(nil, newTestObjectGrouping(), newThinPermission())
			loadUserToCategoryPolices(p)
			return p
		},
	},
}

var bothGroupedPermissions = []struct {
	name string
	ctor func() Permission
}{
	{
		name: "simple permission",
		ctor: func() Permission {
			p := newBothGroupedPermission(newTestSubjectGrouping(), newTestObjectGrouping(), newThinPermission())
			loadUserToArticlePolices(p)
			loadRoleToArticlePolices(p)
			loadUserToCategoryPolices(p)
			loadRoleToCategoryPolices(p)
			return p
		},
	},
}

var _ = Describe("subject grouped permission", func() {
	for _, tp := range subjectGroupedPermissions {
		Describe(tp.name, func() {
			p := tp.ctor()

			Context("init permissions", func() {
				for _, tc := range roleToArticlePolices {
					It("should be permitted", func() {
						Expect(p.Shall(tc.sub, tc.obj, tc.act)).To(BeTrue())
					})
				}
			})

			DescribeTable("object permissions",
				func(obj Object, perms map[Subject]Action) {
					Expect(p.PermissionsOn(obj)).To(Equal(perms))
				},
				Entry("project apollo's permissions", Article("project apollo"), map[Subject]Action{
					Role("2_0"): Read,
					Role("2_1"): ReadWriteExec,
				}),
				Entry("manhattan project's permissions", Article("manhattan project"), map[Subject]Action{
					Role("3_0"): Read,
					Role("3_1"): ReadWrite,
					Role("3_2"): ReadExec,
				}),
			)

			DescribeTable("indirect permissions",
				func(sub Subject, obj Object, act Action) {
					Expect(p.Shall(sub, obj, act)).To(BeTrue())
				},
				Entry("user 0 could Read project apollo", User("0"), Article("project apollo"), Read),
				Entry("user 0 could Read manhattan project", User("0"), Article("manhattan project"), Read),
				Entry("user 4 could Read project apollo", User("4"), Article("project apollo"), Read),
				Entry("user 4 could ReadWrite manhattan project", User("4"), Article("manhattan project"), ReadWrite),
				Entry("user 5 could Exec project apollo", User("5"), Article("project apollo"), Exec),
				Entry("user 5 could Exec manhattan project", User("5"), Article("manhattan project"), Exec),
			)

			DescribeTable("negative permissions",
				func(sub Subject, obj Object, act Action) {
					Expect(p.Shall(sub, obj, act)).To(BeFalse())
				},
				Entry("user 0 shall not Write project apollo", User("0"), Article("project apollo"), Write),
				Entry("user 0 shall not Exec project apollo", User("0"), Article("project apollo"), Exec),
				Entry("user 0 shall not Write manhattan project", User("0"), Article("manhattan project"), Write),
				Entry("user 5 shall not Write manhattan project", User("5"), Article("manhattan project"), Write),
			)

			When("permission being revoked", func() {
				BeforeEach(func() {
					Expect(p.Revoke(Role("2_1"), Article("project apollo"), Exec)).To(Succeed())
					Expect(p.Revoke(Role("3_2"), Article("manhattan project"), Exec)).To(Succeed())
				})

				DescribeTable("indirect subjects",
					func(sub Subject, obj Object) {
						Expect(p.Shall(sub, obj, Exec)).To(BeFalse())
					},
					Entry("user 1 shall not Exec project apollo", User("1"), Article("project apollo")),
					Entry("user 3 shall not Exec project apollo", User("3"), Article("project apollo")),
					Entry("user 5 shall not Exec project apollo", User("5"), Article("project apollo")),
					Entry("user 2 shall not Exec manhattan project", User("2"), Article("manhattan project")),
					Entry("user 5 shall not Exec manhattan project", User("5"), Article("manhattan project")),
					Entry("user 8 shall not Exec manhattan project", User("8"), Article("manhattan project")),
				)
			})
		})
	}
})

var _ = Describe("object grouped permission", func() {
	for _, tp := range objectGroupedPermissions {
		Describe(tp.name, func() {
			p := tp.ctor()

			Describe("init permissions", func() {
				for _, perm := range userToCategoryPolices {
					perm := perm
					It("should be permitted", func() {
						Expect(p.Shall(perm.sub, perm.obj, perm.act)).To(BeTrue())
					})
				}
			})

			DescribeTable("allowed permissions",
				func(user User, art Article, act Action) {
					Expect(p.Shall(user, art, act)).To(BeTrue())
				},
				Entry("user 0 can Read manhattan project", User("0"), Article("manhattan project"), Read),
				Entry("user 0 can Write project apollo", User("0"), Article("project apollo"), Write),
				Entry("user 0 can Read operation overlord", User("0"), Article("operation overlord"), Read),
				Entry("user 1 can Exec operation overlord", User("1"), Article("operation overlord"), Exec),
				Entry("user 2 can Write operation overlord", User("2"), Article("operation overlord"), Write),
				Entry("user 3 can Exec operation overlord", User("3"), Article("operation overlord"), Exec),
			)

			DescribeTable("not allowed permissions",
				func(user User, art Article, act Action) {
					Expect(p.Shall(user, art, act)).To(BeFalse())
				},
				Entry("user 0 shall not Write manhattan project", User("0"), Article("manhattan project"), Write),
				Entry("user 0 shall not Exec manhattan project", User("0"), Article("manhattan project"), Exec),
				Entry("user 1 shall not Write operation overlord", User("1"), Article("operation overlord"), Write),
				Entry("user 1 shall not Exec project apollo", User("1"), Article("project apollo"), Exec),
				Entry("user 4 shall not Read operation overlord", User("4"), Article("operation overlord"), Read),
			)

			When("revoking user 3's Exec permission to war projects", func() {
				BeforeEach(func() {
					Expect(p.Revoke(User("3"), Category("war"), Exec)).To(Succeed())
				})

				DescribeTable("user 3 shall not Exec",
					func(art Article) {
						Expect(p.Shall(User("3"), art, Exec)).To(BeFalse())
					},
					Entry("operation overlord", Article("operation overlord")),
					Entry("manhattan project", Article("manhattan project")),
				)
			})
		})
	}
})

var _ = Describe("both grouped permission", func() {
	for _, tp := range bothGroupedPermissions {
		Describe(tp.name, func() {
			p := tp.ctor()

			Describe("check user to article polices", func() {
				for _, perm := range userToArticlePolices {
					perm := perm
					It("should be permitted", func() {
						Expect(p.Shall(perm.sub, perm.obj, perm.act)).To(BeTrue())
					})
				}
			})

			Describe("check user to category polices", func() {
				for _, perm := range userToCategoryPolices {
					perm := perm
					It("should be permitted", func() {
						Expect(p.Shall(perm.sub, perm.obj, perm.act)).To(BeTrue())
					})
				}
			})

			Describe("check role to article polices", func() {
				for _, perm := range roleToArticlePolices {
					perm := perm
					It("should be permitted", func() {
						Expect(p.Shall(perm.sub, perm.obj, perm.act)).To(BeTrue())
					})
				}
			})

			Describe("check role to category polices", func() {
				for _, perm := range roleToCategoryPolices {
					perm := perm
					It("should be permitted", func() {
						Expect(p.Shall(perm.sub, perm.obj, perm.act)).To(BeTrue())
					})
				}
			})

			DescribeTable("check indirect polices",
				func(user User, art Article, act Action) {
					Expect(p.Shall(user, art, act)).To(BeTrue())
				},
				Entry("user 0 can Read operation overlord", User("0"), Article("operation overlord"), Read),
				Entry("user 1 can Exec operation overlord", User("1"), Article("operation overlord"), Exec),
				Entry("user 1 can Write manhattan project", User("1"), Article("manhattan project"), Write),
				Entry("user 2 can Exec manhattan project", User("2"), Article("manhattan project"), Exec),
			)
		})
	}
})
