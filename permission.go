package rbac

type Action interface {
	Action() string
}

type Permission struct {
	Sub Subject
	Obj Object
	Act Action
}

type Permitter interface {
	Permit(Subject, Object, Action) error
	Revoke(Subject, Object, Action) error
	Shall(Subject, Object, Action) error

	Permissions(Subject) ([]Permission, error)
	PermittedSubjects(Object) ([]Permission, error)
}
