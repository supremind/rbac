package grouping

import (
	"github.com/houz42/rbac/types"
)

var _ grouping = (*fatGrouping)(nil)

// fatGrouping caches more information to speed up querying
// fatGrouping is faster on quering, and slower on removing comprared to slimGrouping
type fatGrouping struct {
	slim slimGrouping // no sense to use another implementation

	memberGroups map[types.Member]map[types.Group]struct{}
	groupMembers map[types.Group]map[types.Member]struct{}

	allMembers map[types.Member]struct{}
	allGroups  map[types.Group]struct{}
}

func newFatGrouping() *fatGrouping {
	return &fatGrouping{
		slim:         *newSlimGrouping(),
		memberGroups: make(map[types.Member]map[types.Group]struct{}),
		groupMembers: make(map[types.Group]map[types.Member]struct{}),
		allMembers:   make(map[types.Member]struct{}),
		allGroups:    make(map[types.Group]struct{}),
	}
}

func (g *fatGrouping) Join(ent types.Entity, group types.Group) error {
	if e := g.slim.Join(ent, group); e != nil {
		return e
	}

	if _, ok := g.groupMembers[group]; !ok {
		g.groupMembers[group] = make(map[types.Member]struct{})
	}
	g.allGroups[group] = struct{}{}

	switch ent.(type) {
	case types.Member:
		member := ent.(types.Member)
		if _, ok := g.memberGroups[member]; !ok {
			g.memberGroups[member] = make(map[types.Group]struct{})
		}
		g.allMembers[member] = struct{}{}

		g.memberGroups[member][group] = struct{}{}
		g.groupMembers[group][member] = struct{}{}

	case types.Group:
		subGroup := ent.(types.Group)
		g.allGroups[subGroup] = struct{}{}

		for member := range g.groupMembers[subGroup] {
			g.memberGroups[member][group] = struct{}{}
			g.groupMembers[group][member] = struct{}{}
		}
	}

	return nil
}

func (g *fatGrouping) Leave(ent types.Entity, group types.Group) error {

	switch ent.(type) {
	case types.Member:
		if e := g.slim.Leave(ent, group); e != nil {
			return e
		}

		member := ent.(types.Member)
		delete(g.memberGroups[member], group)
		delete(g.groupMembers[group], member)

	case types.Group:
		subGroup := ent.(types.Group)
		members := g.groupMembers[subGroup]
		if e := g.slim.Leave(ent, group); e != nil {
			return e
		}

		for member := range members {
			if e := g.rebuildOnRemoveRule(member); e != nil {
				return e
			}
		}
	}

	return nil
}

func (g *fatGrouping) IsIn(member types.Member, group types.Group) (bool, error) {
	if members, ok := g.groupMembers[group]; ok {
		_, ok := members[member]
		return ok, nil
	}
	return false, nil
}

func (g *fatGrouping) AllGroups() (map[types.Group]struct{}, error) {
	return g.allGroups, nil
}

func (g *fatGrouping) AllMembers() (map[types.Member]struct{}, error) {
	return g.allMembers, nil
}

func (g *fatGrouping) GroupsOf(mem types.Member) (map[types.Group]struct{}, error) {
	return g.memberGroups[mem], nil
}

func (g *fatGrouping) MembersIn(group types.Group) (map[types.Member]struct{}, error) {
	return g.groupMembers[group], nil
}

func (g *fatGrouping) immediateGroupsOf(ent types.Entity) (map[types.Group]struct{}, error) {
	return g.slim.immediateGroupsOf(ent)
}

func (g *fatGrouping) immediateEntitiesIn(group types.Group) (map[types.Entity]struct{}, error) {
	return g.slim.immediateEntitiesIn(group)
}

func (g *fatGrouping) RemoveGroup(group types.Group) error {
	if e := g.slim.RemoveGroup(group); e != nil {
		return e
	}

	members := g.groupMembers[group]
	delete(g.allGroups, group)
	delete(g.groupMembers, group)

	for member := range members {
		if e := g.rebuildOnRemoveRule(member); e != nil {
			return e
		}
	}

	return nil
}

func (g *fatGrouping) RemoveMember(member types.Member) error {
	if e := g.slim.RemoveMember(member); e != nil {
		return e
	}

	for group := range g.memberGroups[member] {
		delete(g.groupMembers[group], member)
	}
	delete(g.allMembers, member)
	delete(g.memberGroups, member)

	return nil
}

func (g *fatGrouping) rebuildOnRemoveRule(mem types.Member) error {
	groups, e := g.slim.groupsOf(mem)
	if e != nil {
		return e
	}

	removing := make(map[types.Group]struct{}, len(g.memberGroups[mem])-len(groups))
	for group := range g.memberGroups[mem] {
		if _, ok := groups[group]; !ok {
			removing[group] = struct{}{}
		}
	}

	g.memberGroups[mem] = groups
	for group := range removing {
		delete(g.groupMembers[group], mem)
	}

	return nil
}
