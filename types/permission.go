package types

// Subject is a User or a Role to perform actions on Objects
// fixme: define it as a meaningful type other than an empty interface
type Subject interface{}

// Object is an Article or a Category for Subjects perform actions on
// fixme: define it as a meaningful type other than an empty interface
type Object interface{}

// Permission tells if a Subject can perform an Action on an Object based on given polices
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
