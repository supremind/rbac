package types

// Permission knows permission assignment, and tells if a subject is permitted to perform some action to an object
type Permission interface {
	// Permit subject to perform action on object
	Permit(Subject, Object, Action) error

	// Revoke permission for subject to perform action on object
	Revoke(Subject, Object, Action) error

	// Shall subject to perform action on object
	Shall(Subject, Object, Action) (bool, error)

	// PermissionsOn object for all subjects
	PermissionsOn(Object) (map[Subject]Action, error)

	// PermissionsFor subject on all objects
	PermissionsFor(Subject) (map[Object]Action, error)

	// PermittedActions for subject on object
	PermittedActions(Subject, Object) (Action, error)
}
