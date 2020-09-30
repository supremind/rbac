package grouping

import (
	"github.com/houz42/rbac/types"
)

var _ grouping = (*fatGrouping)(nil)

// fatGrouping caches more information to speed up querying
// fatGrouping is faster on quering, and slower on removing comprared to slimGrouping
type fatGrouping struct {
	slim slimGrouping // no sense to use another implementation

	memberGroups  map[types.Member]map[types.Group]struct{}
	groupMembers  map[types.Group]map[types.Member]struct{}
	groupUpward   map[types.Group]map[types.Group]struct{}
	groupDownward map[types.Group]map[types.Group]struct{}
}

func newFatGrouping() *fatGrouping {
	return &fatGrouping{
		slim:          *newSlimGrouping(),
		memberGroups:  make(map[types.Member]map[types.Group]struct{}),
		groupMembers:  make(map[types.Group]map[types.Member]struct{}),
		groupUpward:   make(map[types.Group]map[types.Group]struct{}),
		groupDownward: make(map[types.Group]map[types.Group]struct{}),
	}
}

func (g *fatGrouping) Join(ent types.Entity, group types.Group) error {
	if e := g.slim.Join(ent, group); e != nil {
		return e
	}

	switch ent.(type) {
	case types.Member:
		g.joinMemberToGroup(ent.(types.Member), group)

	case types.Group:
		subGroup := ent.(types.Group)

		for member := range g.groupMembers[subGroup] {
			g.joinMemberToGroup(member, group)
		}

		g.joinGroupToGroup(subGroup, group)
	}

	return nil
}

func (g *fatGrouping) joinMemberToGroup(member types.Member, group types.Group) {
	if _, ok := g.memberGroups[member]; !ok {
		g.memberGroups[member] = make(map[types.Group]struct{})
	}
	g.memberGroups[member][group] = struct{}{}

	if _, ok := g.groupMembers[group]; !ok {
		g.groupMembers[group] = make(map[types.Member]struct{})
	}
	g.groupMembers[group][member] = struct{}{}

	for upper := range g.groupUpward[group] {
		g.memberGroups[member][upper] = struct{}{}
		g.groupMembers[group][member] = struct{}{}
	}
}

func (g *fatGrouping) joinGroupToGroup(sub, super types.Group) {
	if _, ok := g.groupDownward[super]; !ok {
		g.groupDownward[super] = make(map[types.Group]struct{})
	}
	g.groupDownward[super][sub] = struct{}{}

	if _, ok := g.groupUpward[sub]; !ok {
		g.groupUpward[sub] = make(map[types.Group]struct{})
	}
	g.groupUpward[sub][super] = struct{}{}

	for upper := range g.groupUpward[super] {
		for lower := range g.groupDownward[sub] {
			g.groupUpward[lower][upper] = struct{}{}
			g.groupDownward[upper][lower] = struct{}{}
		}
	}
}

func (g *fatGrouping) Leave(ent types.Entity, group types.Group) error {
	if e := g.slim.Leave(ent, group); e != nil {
		return e
	}

	switch ent.(type) {
	case types.Member:
		g.leaveMemberFromGroup(ent.(types.Member), group)

	case types.Group:
		sub := ent.(types.Group)
		g.leaveGroupFromGroup(sub, group)

		for member := range g.groupMembers[sub] {
			g.leaveMemberFromGroup(member, group)
		}

	}

	return nil
}

func (g *fatGrouping) leaveMemberFromGroup(member types.Member, group types.Group) {
	for group := range g.memberGroups[member] {
		delete(g.groupMembers[group], member)
	}
	g.memberGroups[member] = make(map[types.Group]struct{})

	// rebuild member to group mappings
	for group := range g.slim.parents[member] {
		g.memberGroups[member][group] = struct{}{}
		g.groupMembers[group][member] = struct{}{}

		for super := range g.groupUpward[group] {
			g.memberGroups[member][super] = struct{}{}
			g.groupMembers[super][member] = struct{}{}
		}
	}
}

func (g *fatGrouping) leaveGroupFromGroup(sub, super types.Group) {
	lowers := []types.Group{sub}
	for len(lowers) > 0 {
		curr := lowers[0]
		lowers = lowers[1:]

		g.rebuildUpward(curr)

		for lower := range g.slim.children[curr] {
			if ll, ok := lower.(types.Group); ok {
				lowers = append(lowers, ll)
			}
		}
	}

	uppers := []types.Group{super}
	for len(uppers) > 0 {
		curr := uppers[0]
		uppers = uppers[1:]

		g.rebuildDownward(curr)

		for upper := range g.slim.parents[curr] {
			uppers = append(uppers, upper)
		}
	}
}

func (g *fatGrouping) rebuildUpward(sub types.Group) {
	for upper := range g.groupUpward[sub] {
		delete(g.groupDownward[upper], sub)
	}
	g.groupUpward[sub] = make(map[types.Group]struct{})

	for upper := range g.slim.parents[sub] {
		g.groupUpward[sub][upper] = struct{}{}
		g.groupDownward[upper][sub] = struct{}{}

		for super := range g.groupUpward[upper] {
			g.groupUpward[sub][super] = struct{}{}
			g.groupDownward[super][super] = struct{}{}
		}
	}
}

func (g *fatGrouping) rebuildDownward(super types.Group) {
	for lower := range g.groupDownward[super] {
		delete(g.groupUpward[lower], super)
	}
	g.groupDownward[super] = make(map[types.Group]struct{})

	for lower := range g.slim.children[super] {
		if ll, ok := lower.(types.Group); ok {
			g.groupDownward[super][ll] = struct{}{}
			g.groupUpward[ll][super] = struct{}{}

			for lower := range g.groupDownward[ll] {
				g.groupDownward[super][lower] = struct{}{}
				g.groupUpward[lower][super] = struct{}{}
			}
		}
	}
}

func (g *fatGrouping) IsIn(member types.Member, group types.Group) (bool, error) {
	if members, ok := g.groupMembers[group]; ok {
		_, ok := members[member]
		return ok, nil
	}
	return false, nil
}

func (g *fatGrouping) AllGroups() (map[types.Group]struct{}, error) {
	groups := make(map[types.Group]struct{}, len(g.groupMembers))
	for group := range g.groupMembers {
		groups[group] = struct{}{}
	}
	for group := range g.groupUpward {
		groups[group] = struct{}{}
	}
	for group := range g.groupDownward {
		groups[group] = struct{}{}
	}
	return groups, nil
}

func (g *fatGrouping) AllMembers() (map[types.Member]struct{}, error) {
	members := make(map[types.Member]struct{}, len(g.memberGroups))
	for member := range g.memberGroups {
		members[member] = struct{}{}
	}
	return members, nil
}

func (g *fatGrouping) GroupsOf(ent types.Entity) (map[types.Group]struct{}, error) {
	switch ent.(type) {
	case types.Member:
		return g.memberGroups[ent.(types.Member)], nil
	case types.Group:
		return g.groupUpward[ent.(types.Group)], nil
	}

	return map[types.Group]struct{}{}, nil
}

func (g *fatGrouping) MembersIn(group types.Group) (map[types.Member]struct{}, error) {
	return g.groupMembers[group], nil
}

func (g *fatGrouping) RemoveGroup(group types.Group) error {
	if e := g.slim.RemoveGroup(group); e != nil {
		return e
	}

	for lower := range g.groupDownward[group] {
		g.leaveGroupFromGroup(lower, group)
	}
	delete(g.groupDownward, group)

	for upper := range g.groupUpward[group] {
		g.leaveGroupFromGroup(group, upper)
	}
	delete(g.groupUpward, group)

	for member := range g.groupMembers[group] {
		g.leaveMemberFromGroup(member, group)
	}
	delete(g.groupMembers, group)

	return nil
}

func (g *fatGrouping) RemoveMember(member types.Member) error {
	if e := g.slim.RemoveMember(member); e != nil {
		return e
	}

	for group := range g.memberGroups[member] {
		delete(g.groupMembers[group], member)
	}
	delete(g.memberGroups, member)

	return nil
}

func (g *fatGrouping) immediateGroupsOf(ent types.Entity) (map[types.Group]struct{}, error) {
	return g.slim.immediateGroupsOf(ent)
}

func (g *fatGrouping) immediateEntitiesIn(group types.Group) (map[types.Entity]struct{}, error) {
	return g.slim.immediateEntitiesIn(group)
}
