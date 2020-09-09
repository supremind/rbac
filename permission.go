package rbac

type Permitter interface {
	Permit(Subject, Object, Action) error
	Revoke(Subject, Object, Action) error
	Shall(Subject, Object, Action) (bool, error)

	PermissionsTo(Object) (map[Subject]Action, error)
	PermissionsFor(Subject) (map[Object]Action, error)

	PermittedActions(Subject, Object) (Action, error)
}
