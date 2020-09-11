package fake

import (
	"context"

	"github.com/supremind/rbac"
)

type GroupingPersister struct {
	policies map[rbac.Entity]map[rbac.Group]struct{}
	changes  chan rbac.GroupingPolicyChange
}

func NewGroupingPersister(ctx context.Context, initPolices ...rbac.GroupingPolicy) *GroupingPersister {
	gp := &GroupingPersister{
		policies: make(map[rbac.Entity]map[rbac.Group]struct{}),
		changes:  make(chan rbac.GroupingPolicyChange),
	}

	for _, policy := range initPolices {
		if gp.policies[policy.Entity] == nil {
			gp.policies[policy.Entity] = make(map[rbac.Group]struct{})
		}
		gp.policies[policy.Entity][policy.Group] = struct{}{}
	}

	go func() {
		<-ctx.Done()
		close(gp.changes)
	}()

	return gp
}

func (p *GroupingPersister) Insert(ent rbac.Entity, group rbac.Group) error {
	if p.policies[ent] != nil {
		if _, ok := p.policies[ent][group]; ok {
			return nil
		}
	} else {
		p.policies[ent] = make(map[rbac.Group]struct{})
	}

	p.policies[ent][group] = struct{}{}
	p.changes <- rbac.GroupingPolicyChange{
		GroupingPolicy: rbac.GroupingPolicy{
			Entity: ent,
			Group:  group,
		},
		Method: rbac.PersistInsert,
	}

	return nil
}

func (p *GroupingPersister) Remove(ent rbac.Entity, group rbac.Group) error {
	if p.policies[ent] == nil {
		return nil
	}
	if _, ok := p.policies[ent][group]; !ok {
		return nil
	}

	delete(p.policies[ent], group)
	p.changes <- rbac.GroupingPolicyChange{
		GroupingPolicy: rbac.GroupingPolicy{
			Entity: ent,
			Group:  group,
		},
		Method: rbac.PersistDelete,
	}

	return nil
}

func (p *GroupingPersister) RemoveByGroup(group rbac.Group) error {
	removes := make([]rbac.GroupingPolicy, 0)

	for ent, groups := range p.policies {
		for group := range groups {
			removes = append(removes, rbac.GroupingPolicy{Entity: ent, Group: group})
		}
	}

	for _, remove := range removes {
		p.Remove(remove.Entity, remove.Group)
	}
	return nil
}

func (p *GroupingPersister) RemoveByIndividual(ind rbac.Individual) error {
	groups := p.policies[ind]
	if len(groups) == 0 {
		return nil
	}

	removes := make([]rbac.GroupingPolicy, 0, len(groups))
	for group := range groups {
		removes = append(removes, rbac.GroupingPolicy{Entity: ind, Group: group})
	}

	delete(p.policies, ind)
	for _, remove := range removes {
		p.changes <- rbac.GroupingPolicyChange{GroupingPolicy: remove, Method: rbac.PersistDelete}
	}
	return nil
}

func (p *GroupingPersister) List() ([]rbac.GroupingPolicy, error) {
	polices := make([]rbac.GroupingPolicy, 0, len(p.policies))
	for ent, groups := range p.policies {
		for group := range groups {
			polices = append(polices, rbac.GroupingPolicy{Entity: ent, Group: group})
		}
	}

	return polices, nil
}

func (p *GroupingPersister) Watch(ctx context.Context) (<-chan rbac.GroupingPolicyChange, error) {
	return p.changes, nil
}
