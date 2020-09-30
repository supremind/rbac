package filter

import (
	"context"
	"sync"

	"github.com/houz42/rbac/types"
)

type permissionPersisterFilter struct {
	types.PermissionPersister
	changes map[types.PermissionPolicyChange]struct{}
	sync.RWMutex
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

	f.Lock()
	f.changes[change] = struct{}{}
	f.Unlock()

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

	f.Lock()
	f.changes[change] = struct{}{}
	f.Unlock()

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

	f.Lock()
	f.changes[change] = struct{}{}
	f.Unlock()

	return f.PermissionPersister.Remove(sub, obj)
}

func (f *permissionPersisterFilter) Watch(ctx context.Context) (<-chan types.PermissionPolicyChange, error) {
	in, e := f.PermissionPersister.Watch(ctx)
	if e != nil {
		return nil, e
	}

	out := make(chan types.PermissionPolicyChange)

	go func() {
		defer close(out)

		for change := range in {
			f.RLock()
			_, ok := f.changes[change]
			f.RUnlock()

			if ok {
				f.Lock()
				delete(f.changes, change)
				f.Unlock()
			} else {
				out <- change
			}
		}
	}()

	return out, nil
}
