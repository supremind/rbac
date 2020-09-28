package filter

import "github.com/houz42/rbac/types"

type permissionPersisterFilter struct {
	types.PermissionPersister
	changes map[types.PermissionPolicyChange]struct{}
}

// NewPermissionPersister checks if the incoming changes are made by the inner persister itself,
// and does not call it again if true
func NewPermissionPersister(p types.PermissionPersister) *permissionPersisterFilter {
	return &permissionPersisterFilter{
		PermissionPersister: p,
		changes:             make(map[types.PermissionPolicyChange]struct{}),
	}
}

// Insert a permission policy to the persister
func (f *permissionPersisterFilter) Insert(sub types.Subject, obj types.Object, act types.Action) error {
	change := types.PermissionPolicyChange{
		PermissionPolicy: types.PermissionPolicy{
			Subject: sub,
			Object:  obj,
			Action:  act,
		},
		Method: types.PersistInsert,
	}

	if _, ok := f.changes[change]; ok {
		delete(f.changes, change)
		return nil
	}

	f.changes[change] = struct{}{}
	return f.PermissionPersister.Insert(sub, obj, act)
}

// Update a permission policy to the persister
func (f *permissionPersisterFilter) Update(sub types.Subject, obj types.Object, act types.Action) error {
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
	return f.PermissionPersister.Update(sub, obj, act)
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
