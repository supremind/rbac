package rbac

import "strings"

type Action uint16

const (
	Exec Action = 1 << iota
	Write
	Read

	None Action = 0

	ReadWrite     = Read | Write
	ReadExec      = Read | Exec
	ReadWriteExec = Read | Write | Exec

	allActions = ReadWriteExec
)

func (a Action) IsIn(b Action) bool {
	return a|b == b
}

func (a Action) Includes(b Action) bool {
	return b.IsIn(a)
}

func (a Action) Difference(b Action) Action {
	return a &^ b
}

func (a Action) Split() []Action {
	out := make([]Action, 0)
	op := Action(1)
	for op <= a {
		if op&a > 0 {
			out = append(out, op)
		}
		op <<= 1
	}
	return out
}

func (a Action) String() string {
	as := a.Split()
	ns := make([]string, 0, len(as))
	for _, a := range as {
		ns = append(ns, a.name())
	}
	return strings.Join(ns, "|")
}

func (a Action) name() string {
	n, ok := map[Action]string{
		Read:  "read",
		Write: "write",
		Exec:  "exec",
	}[a]
	if !ok {
		n = "unknown"
	}
	return n
}
