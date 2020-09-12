package fake

import (
	"context"

	"github.com/houz42/rbac/types"
)

type groupingPersister struct {
	policies map[types.Entity]map[types.Group]struct{}
	changes  chan types.GroupingPolicyChange
}

func NewGroupingPersister(ctx context.Context, initPolices ...types.GroupingPolicy) *groupingPersister {
	gp := &groupingPersister{
		policies: make(map[types.Entity]map[types.Group]struct{}),
		changes:  make(chan types.GroupingPolicyChange),
	}

	for _, policy := range initPolices {
		if gp.policies[policy.Entity] == nil {
			gp.policies[policy.Entity] = make(map[types.Group]struct{})
		}
		gp.policies[policy.Entity][policy.Group] = struct{}{}
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
			return nil
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

func (p *groupingPersister) RemoveByGroup(group types.Group) error {
	removes := make([]types.GroupingPolicy, 0)

	for ent, groups := range p.policies {
		for group := range groups {
			removes = append(removes, types.GroupingPolicy{Entity: ent, Group: group})
		}
	}

	for _, remove := range removes {
		p.Remove(remove.Entity, remove.Group)
	}
	return nil
}

func (p *groupingPersister) RemoveByIndividual(m types.Member) error {
	groups := p.policies[m]
	if len(groups) == 0 {
		return nil
	}

	removes := make([]types.GroupingPolicy, 0, len(groups))
	for group := range groups {
		removes = append(removes, types.GroupingPolicy{Entity: m, Group: group})
	}

	delete(p.policies, m)
	for _, remove := range removes {
		p.changes <- types.GroupingPolicyChange{GroupingPolicy: remove, Method: types.PersistDelete}
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
