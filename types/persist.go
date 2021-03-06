package types

import "context"

// GroupingPersister persists member-group relationship polices to an external storage
type GroupingPersister interface {
	// Insert inserts a policy to the persister
	Insert(Entity, Group) error

	// Remove a policy from the persister
	Remove(Entity, Group) error

	// List all policies from the persister
	List() ([]GroupingPolicy, error)

	// Watch any changes occurred about the policies in the persister
	Watch(context.Context) (<-chan GroupingPolicyChange, error)
}

// PermissionPersister persists subject-object-action permission polices to an external storage
type PermissionPersister interface {
	// Insert a permission policy to the persister
	Insert(Subject, Object, Action) error

	// Update a permission policy to the persister
	Update(Subject, Object, Action) error

	// Remove a permission policy from the persister
	Remove(Subject, Object) error

	// List all polices from the persister
	List() ([]PermissionPolicy, error)

	// Watch any changes occurred about the polices in the persister
	Watch(context.Context) (<-chan PermissionPolicyChange, error)
}

// GroupingPolicy is an entity-group releationship policy
type GroupingPolicy struct {
	Entity Entity
	Group  Group
}

// GroupingPolicyChange denotes an changing event about a GroupingPolicy
type GroupingPolicyChange struct {
	GroupingPolicy
	Method PersistMethod
}

// PermissionPolicy is a subject-object-action permission policy
type PermissionPolicy struct {
	Subject Subject
	Object  Object
	Action  Action
}

// PermissionPolicyChange denotes an changing event about a PermissionPolicy
type PermissionPolicyChange struct {
	PermissionPolicy
	Method PersistMethod
}

// PersistMethod defines what happened about the policies
type PersistMethod string

// possible changes could be happened about policies
const (
	PersistInsert PersistMethod = "insert"
	PersistDelete PersistMethod = "delete"
	PersistUpdate PersistMethod = "update"
)
