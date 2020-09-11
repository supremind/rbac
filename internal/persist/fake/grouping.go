package fake

import (
	"context"

	. "github.com/supremind/rbac/types"
)

type groupingPersister struct {
	policies map[Entity]map[Group]struct{}
	changes  chan GroupingPolicyChange
}

func NewGroupingPersister(ctx context.Context, initPolices ...GroupingPolicy) *groupingPersister {
	gp := &groupingPersister{
		policies: make(map[Entity]map[Group]struct{}),
		changes:  make(chan GroupingPolicyChange),
	}

	for _, policy := range initPolices {
		if gp.policies[policy.Entity] == nil {
			gp.policies[policy.Entity] = make(map[Group]struct{})
		}
		gp.policies[policy.Entity][policy.Group] = struct{}{}
	}

	go func() {
		<-ctx.Done()
		close(gp.changes)
	}()

	return gp
}

func (p *groupingPersister) Insert(ent Entity, group Group) error {
	if p.policies[ent] != nil {
		if _, ok := p.policies[ent][group]; ok {
			return nil
		}
	} else {
		p.policies[ent] = make(map[Group]struct{})
	}

	p.policies[ent][group] = struct{}{}
	p.changes <- GroupingPolicyChange{
		GroupingPolicy: GroupingPolicy{
			Entity: ent,
			Group:  group,
		},
		Method: PersistInsert,
	}

	return nil
}

func (p *groupingPersister) Remove(ent Entity, group Group) error {
	if p.policies[ent] == nil {
		return nil
	}
	if _, ok := p.policies[ent][group]; !ok {
		return nil
	}

	delete(p.policies[ent], group)
	p.changes <- GroupingPolicyChange{
		GroupingPolicy: GroupingPolicy{
			Entity: ent,
			Group:  group,
		},
		Method: PersistDelete,
	}

	return nil
}

func (p *groupingPersister) RemoveByGroup(group Group) error {
	removes := make([]GroupingPolicy, 0)

	for ent, groups := range p.policies {
		for group := range groups {
			removes = append(removes, GroupingPolicy{Entity: ent, Group: group})
		}
	}

	for _, remove := range removes {
		p.Remove(remove.Entity, remove.Group)
	}
	return nil
}

func (p *groupingPersister) RemoveByIndividual(ind Individual) error {
	groups := p.policies[ind]
	if len(groups) == 0 {
		return nil
	}

	removes := make([]GroupingPolicy, 0, len(groups))
	for group := range groups {
		removes = append(removes, GroupingPolicy{Entity: ind, Group: group})
	}

	delete(p.policies, ind)
	for _, remove := range removes {
		p.changes <- GroupingPolicyChange{GroupingPolicy: remove, Method: PersistDelete}
	}
	return nil
}

func (p *groupingPersister) List() ([]GroupingPolicy, error) {
	polices := make([]GroupingPolicy, 0, len(p.policies))
	for ent, groups := range p.policies {
		for group := range groups {
			polices = append(polices, GroupingPolicy{Entity: ent, Group: group})
		}
	}

	return polices, nil
}

func (p *groupingPersister) Watch(ctx context.Context) (<-chan GroupingPolicyChange, error) {
	return p.changes, nil
}
