package filter

import (
	"context"
	"sync"

	"github.com/supremind/rbac/types"
)

type groupingPersisterFilter struct {
	types.GroupingPersister
	changes map[types.GroupingPolicyChange]struct{}
	sync.RWMutex
}

// NewGroupingPersister checks if the incoming changes are made by the inner persister itself,
// and does not call it again if true
func NewGroupingPersister(p types.GroupingPersister) *groupingPersisterFilter {
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

	f.Lock()
	f.changes[change] = struct{}{}
	f.Unlock()

	return f.GroupingPersister.Insert(ent, group)
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

	f.Lock()
	f.changes[change] = struct{}{}
	f.Unlock()

	return f.GroupingPersister.Remove(ent, group)
}

func (f *groupingPersisterFilter) Watch(ctx context.Context) (<-chan types.GroupingPolicyChange, error) {
	in, e := f.GroupingPersister.Watch(ctx)
	if e != nil {
		return nil, e
	}

	out := make(chan types.GroupingPolicyChange)

	go func() {
		defer close(out)

		for {
			select {

			case <-ctx.Done():
				return
			default:
				change, ok := <-in
				if !ok {
					return
				}

				f.RLock()
				_, ok = f.changes[change]
				f.RUnlock()

				if ok {
					f.Lock()
					delete(f.changes, change)
					f.Unlock()
				} else {
					out <- change
				}
			}
		}
	}()

	return out, nil
}
