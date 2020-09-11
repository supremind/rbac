package rbac

import "context"

type GroupingPersister interface {
	Insert(Entity, Group) error
	Remove(Entity, Group) error
	RemoveByGroup(Group) error
	RemoveByIndividual(Individual) error
	List() ([]GroupingPolicy, error)
	Watch(context.Context) (<-chan GroupingPolicyChange, error)
}

type PermissionPersister interface {
	Upsert(Subject, Object, Action) error
	Remove(Subject, Object) error
	List() ([]PermissionPolicy, error)
	Watch(context.Context) (<-chan PermissionChange, error)
}

type GroupingPolicy struct {
	Entity Entity
	Group  Group
}

type GroupingPolicyChange struct {
	GroupingPolicy
	Method PersistMethod
}

type PermissionPolicy struct {
	Subject Subject
	Object  Object
	Action  Action
}

type PermissionChange struct {
	PermissionPolicy
	Method PersistMethod
}

type PersistMethod string

const (
	PersistInsert PersistMethod = "insert"
	PersistDelete PersistMethod = "delete"
	PersistUpdate PersistMethod = "update"
)
