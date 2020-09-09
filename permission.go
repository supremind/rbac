package rbac

type Subject interface{}

type Object interface{}

type Permission interface {
	Permit(Subject, Object, Action) error
	Revoke(Subject, Object, Action) error

	Shall(Subject, Object, Action) (bool, error)

	PermissionsTo(Object) (map[Subject]Action, error)
	PermissionsFor(Subject) (map[Object]Action, error)

	PermittedActions(Subject, Object) (Action, error)
}
