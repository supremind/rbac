package filter

import "github.com/houz42/rbac/types"

type groupingPersisterFilter struct {
	types.GroupingPersister
	changes map[types.GroupingPolicyChange]struct{}
}

// NewGroupingPersisterFilter checks if the incoming changes are made by the inner persister itself,
// and does not call it again it is true
func NewGroupingPersisterFilter(p types.GroupingPersister) *groupingPersisterFilter {
	return &groupingPersisterFilter{
		GroupingPersister: p,
		changes:           make(map[types.GroupingPolicyChange]struct{}),
	}
}

// Insert inserts a policy to the persister
func (f *groupingPersisterFilter) Insert(ent types.Entity, group types.Group) error {
	change := types.GroupingPolicyChange{
		GroupingPolicy: types.GroupingPolicy{
			Entity: ent,
			Group:  group,
		},
		Method: types.PersistInsert,
	}

	if _, ok := f.changes[change]; ok {
		delete(f.changes, change)
		return nil
	}

	f.changes[change] = struct{}{}
	return f.Insert(ent, group)
}

// Remove a policy from the persister
func (f *groupingPersisterFilter) Remove(ent types.Entity, group types.Group) error {
	change := types.GroupingPolicyChange{
		GroupingPolicy: types.GroupingPolicy{
			Entity: ent,
			Group:  group,
		},
		Method: types.PersistDelete,
	}

	if _, ok := f.changes[change]; ok {
		delete(f.changes, change)
		return nil
	}

	f.changes[change] = struct{}{}
	return f.Remove(ent, group)
}

type permissionPersisterFilter struct {
	types.PermissionPersister
	changes map[types.PermissionPolicyChange]struct{}
}

// NewPermissionPersisterFilter checks if the incoming changes are made by the inner persister itself,
// and does not call it again it is true
func NewPermissionPersisterFilter(p types.PermissionPersister) *permissionPersisterFilter {
	return &permissionPersisterFilter{
		PermissionPersister: p,
		changes:             make(map[types.PermissionPolicyChange]struct{}),
	}
}

// Upsert insert or update a permission policy to the persister
func (f *permissionPersisterFilter) Upsert(sub types.Subject, obj types.Object, act types.Action) error {
	change := types.PermissionPolicyChange{
		PermissionPolicy: types.PermissionPolicy{
			Subject: sub,
			Object:  obj,
			Action:  act,
		},
		Method: types.PersistUpdate,
	}

	if _, ok := f.changes[change]; ok {
		delete(f.changes, change)
		return nil
	}

	f.changes[change] = struct{}{}
	return f.PermissionPersister.Upsert(sub, obj, act)
}

// Remove a permission policy from the persister
func (f *permissionPersisterFilter) Remove(sub types.Subject, obj types.Object) error {
	change := types.PermissionPolicyChange{
		PermissionPolicy: types.PermissionPolicy{
			Subject: sub,
			Object:  obj,
		},
		Method: types.PersistDelete,
	}

	if _, ok := f.changes[change]; ok {
		delete(f.changes, change)
		return nil
	}

	f.changes[change] = struct{}{}
	return f.PermissionPersister.Remove(sub, obj)
}
