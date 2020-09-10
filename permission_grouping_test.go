package rbac

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var roleToArticlePermissions = []struct {
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

var userToCategoryPermissions = []struct {
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

var roleToCategoryPermissions = []struct {
}{}

var _ = Describe("subject grouped", func() {
	for _, tp := range []struct {
		name string
		ctor func(g Grouping) Permission
	}{
		{
			name: "subject grouped",
			ctor: func(g Grouping) Permission {
				return newSubjectGroupedPermission(g, newThinPermission())
			},
		},
		{
			name: "both grouped",
			ctor: func(g Grouping) Permission {
				return newBothGroupedPermission(g, newFatGrouping(), newThinPermission())
			},
		},
	} {
		Describe(tp.name, func() {
			g := newFatGrouping()
			for user, roles := range userRoles {
				for _, role := range roles {
					Expect(g.Join(user, role)).To(Succeed())
				}
			}
			p := tp.ctor(g)

			for _, tc := range roleToArticlePermissions {
				Expect(p.Permit(tc.sub, tc.obj, tc.act)).To(Succeed())
			}

			Context("init permissions", func() {
				for _, tc := range roleToArticlePermissions {
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

var _ = Describe("object grouped", func() {
	for _, tp := range []struct {
		name string
		ctor func(og Grouping) Permission
	}{
		{
			name: "object grouped",
			ctor: func(og Grouping) Permission {
				return newObjectGroupedPermission(og, newThinPermission())
			},
		},
		{
			name: "both grouped",
			ctor: func(og Grouping) Permission {
				return newBothGroupedPermission(newFatGrouping(), og, newThinPermission())
			},
		},
	} {
		Describe(tp.name, func() {
			g := newFatGrouping()
			for _, tc := range objectGroupings {
				Expect(g.Join(tc.art, tc.cat)).To(Succeed())
			}
			p := tp.ctor(g)

			for _, perm := range userToCategoryPermissions {
				perm := perm
				It("should be inserted", func() {
					Expect(p.Permit(perm.sub, perm.obj, perm.act)).To(Succeed())
				})
			}

			Describe("init permissions", func() {
				for _, perm := range userToCategoryPermissions {
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
