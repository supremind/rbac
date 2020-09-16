package fake

import (
	"context"

	"github.com/houz42/rbac/types"
)

type groupingPersister struct {
	policies map[types.Entity]map[types.Group]struct{}
	changes  chan types.GroupingPolicyChange
}

// NewGroupingPersister returns a fake grouping persister which should not be used in real works
func NewGroupingPersister(ctx context.Context) *groupingPersister {
	gp := &groupingPersister{
		policies: make(map[types.Entity]map[types.Group]struct{}),
		changes:  make(chan types.GroupingPolicyChange, 100),
	}

	go func() {
		<-ctx.Done()
		close(gp.changes)
	}()

	return gp
}

func (p *groupingPersister) Insert(ent types.Entity, group types.Group) error {
	if p.policies[ent] != nil {
		if _, ok := p.policies[ent][group]; ok {
			return types.ErrAlreadyExists
		}
	} else {
		p.policies[ent] = make(map[types.Group]struct{})
	}

	p.policies[ent][group] = struct{}{}
	p.changes <- types.GroupingPolicyChange{
		GroupingPolicy: types.GroupingPolicy{
			Entity: ent,
			Group:  group,
		},
		Method: types.PersistInsert,
	}

	return nil
}

func (p *groupingPersister) Remove(ent types.Entity, group types.Group) error {
	if p.policies[ent] == nil {
		return nil
	}
	if _, ok := p.policies[ent][group]; !ok {
		return nil
	}

	delete(p.policies[ent], group)
	p.changes <- types.GroupingPolicyChange{
		GroupingPolicy: types.GroupingPolicy{
			Entity: ent,
			Group:  group,
		},
		Method: types.PersistDelete,
	}

	return nil
}

func (p *groupingPersister) List() ([]types.GroupingPolicy, error) {
	polices := make([]types.GroupingPolicy, 0, len(p.policies))
	for ent, groups := range p.policies {
		for group := range groups {
			polices = append(polices, types.GroupingPolicy{Entity: ent, Group: group})
		}
	}

	return polices, nil
}

func (p *groupingPersister) Watch(ctx context.Context) (<-chan types.GroupingPolicyChange, error) {
	return p.changes, nil
}

func (p *groupingPersister) Close() {
	close(p.changes)
}
