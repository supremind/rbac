package rbac

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("subject grouped", func() {
	var rolePermissions = []struct {
		sub Subject
		obj Object
		act Action
	}{
		{sub: Role("2_0"), obj: Article("apollo"), act: Read},
		{sub: Role("2_1"), obj: Article("apollo"), act: ReadWriteExec},
		{sub: Role("3_0"), obj: Article("manhattan"), act: Read},
		{sub: Role("3_1"), obj: Article("manhattan"), act: ReadWrite},
		{sub: Role("3_2"), obj: Article("manhattan"), act: ReadExec},
	}

	for _, tp := range []struct {
		name string
		ctor func(g Grouping) Permission
	}{
		{
			name: "subject grouped",
			ctor: func(g Grouping) Permission {
				return newSubjectGroupedPermission(g)
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

			for _, tc := range rolePermissions {
				Expect(p.Permit(tc.sub, tc.obj, tc.act)).To(Succeed())
			}

			Context("init permissions", func() {
				for _, tc := range rolePermissions {
					It("should be permitted", func() {
						Expect(p.Shall(tc.sub, tc.obj, tc.act)).To(BeTrue())
					})
				}
			})

			DescribeTable("object permissions",
				func(obj Object, perms map[Subject]Action) {
					Expect(p.PermissionsTo(obj)).To(Equal(perms))
				},
				Entry("apollo's permissions", Article("apollo"), map[Subject]Action{
					Role("2_0"): Read,
					Role("2_1"): ReadWriteExec,
				}),
				Entry("manhatten's permissions", Article("manhattan"), map[Subject]Action{
					Role("3_0"): Read,
					Role("3_1"): ReadWrite,
					Role("3_2"): ReadExec,
				}),
			)

			DescribeTable("indirect permissions",
				func(sub Subject, obj Object, act Action) {
					Expect(p.Shall(sub, obj, act)).To(BeTrue())
				},
				Entry("user 0 could Read apollo", User("0"), Article("apollo"), Read),
				Entry("user 0 could Read manhatten", User("0"), Article("manhattan"), Read),
				Entry("user 4 could Read apollo", User("4"), Article("apollo"), Read),
				Entry("user 4 could ReadWrite manhatten", User("4"), Article("manhattan"), ReadWrite),
			)
		})
	}
})

var _ = Describe("object grouped", func() {

})
