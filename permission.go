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
	Permit(Permission) error
	Revoke(Permission) error
	Shall(Permission) (bool, error)

	PermissionsTo(Object) ([]Permission, error)
	PermissionsFor(Subject) ([]Permission, error)
}
