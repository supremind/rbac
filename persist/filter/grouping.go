package filter

import "github.com/houz42/rbac/types"

type groupingPersisterFilter struct {
	types.GroupingPersister
	changes map[types.GroupingPolicyChange]struct{}
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

	if _, ok := f.changes[change]; ok {
		delete(f.changes, change)
		return nil
	}

	f.changes[change] = struct{}{}
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

	if _, ok := f.changes[change]; ok {
		delete(f.changes, change)
		return nil
	}

	f.changes[change] = struct{}{}
	return f.GroupingPersister.Remove(ent, group)
}
