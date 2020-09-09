package rbac

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("action", func() {
	DescribeTable("is in",
		func(a, b Action) {
			Expect(a.IsIn(b)).To(BeTrue())
		},
		Entry("read is in read", Read, Read),
		Entry("read is in rw", Read, ReadWrite),
		Entry("exec is in rwx", Read, ReadWriteExec),
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
})
