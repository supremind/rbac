package types_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	. "github.com/houz42/rbac/types"
)

func TestAction(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "action test suit")
}

var _ = Describe("action", func() {
	DescribeTable("is in",
		func(a, b Action) {
			Expect(a.IsIn(b)).To(BeTrue())
		},
		Entry("read is in read", Read, Read),
		Entry("read is in rw", Read, ReadWrite),
		Entry("exec is in rwx", Read, ReadWriteExec),
	)

	DescribeTable("is not in",
		func(a, b Action) {
			Expect(a.IsIn(b)).To(BeFalse())
		},
		Entry("Read is not in Write", Read, Write),
		Entry("Read is not in WriteExec", Read, Write|Exec),
	)

	DescribeTable("split",
		func(joined Action, splitted []interface{}) {
			Expect(joined.Split()).To(ConsistOf(splitted...))
		},
		Entry("read only", Read, []interface{}{Read}),
		Entry("read write", ReadWrite, []interface{}{Read, Write}),
		Entry("read exec", ReadExec, []interface{}{Read, Exec}),
		Entry("read write exec", ReadWriteExec, []interface{}{Read, Write, Exec}),
	)

	When("reset actions", func() {
		methods := ResetActions("GET", "HEAD", "POST", "UPDATE", "PATCH", "DELETE")
		get, head, post, update, patch, delete := methods[0], methods[1], methods[2], methods[3], methods[4], methods[5]

		read := get | head
		edit := update | patch
		write := post | update | patch | delete
		rest := get | post | update | patch | delete

		DescribeTable("is in",
			func(a, b Action) {
				Expect(a.IsIn(b)).To(BeTrue())
			},
			Entry("get is read", get, read),
			Entry("head is read", head, read),
			Entry("post is rest", post, rest),
			Entry("patch is edit", patch, edit),
			Entry("patch is write", patch, write),
		)

		DescribeTable("is not in",
			func(a, b Action) {
				Expect(a.IsIn(b)).To(BeFalse())
			},
			Entry("get is not write", get, write),
			Entry("post is not edit", post, edit),
			Entry("head is not rest", head, rest),
		)

		Describe("all actions", func() {
			Expect(AllActions).To(BeEquivalentTo(1<<len(methods) - 1))
		})
	})
})
