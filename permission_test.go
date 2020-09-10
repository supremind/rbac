package rbac

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var userToArticlePermissions = []struct {
	sub User
	obj Article
	act Action
}{
	{sub: User("alan"), obj: Article("operation market garden"), act: ReadWriteExec},
	{sub: User("karman"), obj: Article("operation market garden"), act: ReadWrite},
	{sub: User("alan"), obj: Article("operation overlord"), act: ReadWriteExec},
	{sub: User("neumann"), obj: Article("operation overlord"), act: Read},
	{sub: User("neumann"), obj: Article("manhattan project"), act: ReadWrite},
	{sub: User("karman"), obj: Article("manhattan project"), act: ReadWriteExec},
	{sub: User("alan"), obj: Article("project apollo"), act: Read},
	{sub: User("karman"), obj: Article("project apollo"), act: ReadWriteExec},
}

var _ = Describe("base permitter implementation", func() {
	var permitters = []struct {
		name string
		p    Permission
	}{
		{
			name: "thin",
			p:    newThinPermission(),
		},
		{
			name: "synced",
			p:    newSyncedPermission(newThinPermission()),
		},
		{
			name: "subject grouped",
			p:    newSubjectGroupedPermission(newFatGrouping(), newThinPermission()),
		},
		{
			name: "object grouped",
			p:    newObjectGroupedPermission(newFatGrouping(), newThinPermission()),
		},
		{
			name: "both grouped",
			p:    newBothGroupedPermission(newFatGrouping(), newFatGrouping(), newThinPermission()),
		},
	}

	for _, tp := range permitters {
		Context(tp.name, func() {
			p := tp.p

			BeforeEach(func() {
				for _, tc := range userToArticlePermissions {
					Expect(p.Permit(tc.sub, tc.obj, tc.act)).To(Succeed())
				}
			})

			Context("check init polices", func() {
				for _, tc := range userToArticlePermissions {
					It("should be allowed", func() {
						Expect(p.Shall(tc.sub, tc.obj, tc.act)).To(BeTrue(), fmt.Sprintf("%s -[%s]-> %s", tc.sub, tc.act, tc.obj))
					})
				}
			})

			DescribeTable("revoke permissions",
				func(sub Subject, obj Object, act Action) {
					Expect(p.Revoke(sub, obj, act)).To(Succeed())
					Expect(p.Shall(sub, obj, act)).NotTo(BeTrue())
				},
				Entry("alan x operation overlord", User("alan"), Article("operation overlord"), Exec),
				Entry("alan r operation overlord", User("alan"), Article("operation overlord"), Read),
				Entry("karman rwx project apollo", User("karman"), Article("project apollo"), ReadWriteExec),
			)

			DescribeTable("query permissions to object",
				func(obj Object, perm map[Subject]Action) {
					Expect(p.PermissionsOn(obj)).To(Equal(perm))
				},
				Entry("permissions to operation market garden", Article("operation market garden"), map[Subject]Action{
					User("alan"):   ReadWriteExec,
					User("karman"): ReadWrite,
				}),
				Entry("permissions to manhattan project", Article("manhattan project"), map[Subject]Action{
					User("neumann"): ReadWrite,
					User("karman"):  ReadWriteExec,
				}),
			)

			DescribeTable("query permissions for subject",
				func(sub Subject, perm map[Object]Action) {
					Expect(p.PermissionsFor(sub)).To(Equal(perm))
				},
				Entry("permissions for alan", User("alan"), map[Object]Action{
					Article("operation market garden"): ReadWriteExec,
					Article("operation overlord"):      ReadWriteExec,
					Article("project apollo"):          Read,
				}),
				Entry("permissions for neumann", User("neumann"), map[Object]Action{
					Article("operation overlord"): Read,
					Article("manhattan project"):  ReadWrite,
				}),
			)

			DescribeTable("query permissions for subject to object",
				func(sub Subject, obj Object, act Action) {
					Expect(p.PermittedActions(sub, obj)).To(Equal(act))
				},
				Entry("alan to manhattan project", User("alan"), Article("manhattan project"), None),
				Entry("alan to operation overlord", User("alan"), Article("operation overlord"), ReadWriteExec),
				Entry("karman to manhattan project", User("karman"), Article("manhattan project"), ReadWriteExec),
			)
		})
	}
})
