package rbac

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

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
			p:    newSubjectGroupedPermission(newFatGrouping()),
		},
		{
			name: "object grouped",
			p:    newObjectGroupedPermission(newFatGrouping()),
		},
		{
			name: "both grouped",
			p:    newBothGroupedPermission(newFatGrouping(), newFatGrouping()),
		},
	}

	var initPermissions = []struct {
		sub Subject
		obj Object
		act Action
	}{
		{sub: User("alan"), obj: Article("market garden"), act: ReadWriteExec},
		{sub: User("karman"), obj: Article("market garden"), act: ReadWrite},
		{sub: User("alan"), obj: Article("overlord"), act: ReadWriteExec},
		{sub: User("neumann"), obj: Article("overlord"), act: Read},
		{sub: User("neumann"), obj: Article("manhattan"), act: ReadWrite},
		{sub: User("karman"), obj: Article("manhattan"), act: ReadWriteExec},
		{sub: User("alan"), obj: Article("apollo"), act: Read},
		{sub: User("karman"), obj: Article("apollo"), act: ReadWriteExec},
	}

	for _, tp := range permitters {
		Context(tp.name, func() {
			p := tp.p

			BeforeEach(func() {
				for _, tc := range initPermissions {
					Expect(p.Permit(tc.sub, tc.obj, tc.act)).To(Succeed())
				}
			})

			Context("check init polices", func() {
				for _, tc := range initPermissions {
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
				Entry("alan x overlord", User("alan"), Article("overlord"), Exec),
				Entry("alan r overlord", User("alan"), Article("overlord"), Read),
				Entry("karman rwx apollo", User("karman"), Article("apollo"), ReadWriteExec),
			)

			DescribeTable("query permissions to object",
				func(obj Object, perm map[Subject]Action) {
					Expect(p.PermissionsTo(obj)).To(Equal(perm))
				},
				Entry("permissions to market garden", Article("market garden"), map[Subject]Action{
					User("alan"):   ReadWriteExec,
					User("karman"): ReadWrite,
				}),
				Entry("permissions to manhattan", Article("manhattan"), map[Subject]Action{
					User("neumann"): ReadWrite,
					User("karman"):  ReadWriteExec,
				}),
			)

			DescribeTable("query permissions for subject",
				func(sub Subject, perm map[Object]Action) {
					Expect(p.PermissionsFor(sub)).To(Equal(perm))
				},
				Entry("permissions for alan", User("alan"), map[Object]Action{
					Article("market garden"): ReadWriteExec,
					Article("overlord"):      ReadWriteExec,
					Article("apollo"):        Read,
				}),
				Entry("permissions for neumann", User("neumann"), map[Object]Action{
					Article("overlord"):  Read,
					Article("manhattan"): ReadWrite,
				}),
			)

			DescribeTable("query permissions for subject to object",
				func(sub Subject, obj Object, act Action) {
					Expect(p.PermittedActions(sub, obj)).To(Equal(act))
				},
				Entry("alan to manhattan", User("alan"), Article("manhattan"), None),
				Entry("alan to overlord", User("alan"), Article("overlord"), ReadWriteExec),
				Entry("karman to manhattan", User("karman"), Article("manhattan"), ReadWriteExec),
			)
		})
	}
})
