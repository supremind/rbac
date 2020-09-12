package grouping

import (
	"github.com/houz42/rbac/types"
)

var _ types.Grouping = (*fatGrouping)(nil)

// fatGrouping caches more information to speed up querying
// fatGrouping is faster on quering, and slower on removing comprared to slimGrouping
type fatGrouping struct {
	slim slimGrouping // no sense to use another implementation

	// entity => all groups it belongs to
	groups map[types.Entity]map[types.Group]struct{}
	// group => all members belongs to it
	members map[types.Group]map[types.Member]struct{}

	allMembers map[types.Member]struct{}
	allGroups  map[types.Group]struct{}
}

// NewFatGrouping creates a new grouping faster than slimGrouping, but still should not be used in production
func NewFatGrouping() *fatGrouping {
	return &fatGrouping{
		slim:       *NewSlimGrouping(),
		groups:     make(map[types.Entity]map[types.Group]struct{}),
		members:    make(map[types.Group]map[types.Member]struct{}),
		allMembers: make(map[types.Member]struct{}),
		allGroups:  make(map[types.Group]struct{}),
	}
}

func (g *fatGrouping) Join(ent types.Entity, group types.Group) error {
	if e := g.slim.Join(ent, group); e != nil {
		return e
	}

	g.allGroups[group] = struct{}{}
	if member, ok := ent.(types.Member); ok {
		g.allMembers[member] = struct{}{}
	}

	if g.groups[ent] == nil {
		g.groups[ent] = make(map[types.Group]struct{})
	}
	g.groups[ent][group] = struct{}{}
	for rr := range g.groups[group] {
		g.groups[ent][rr] = struct{}{}
	}

	if g.members[group] == nil {
		g.members[group] = make(map[types.Member]struct{})
	}
	if member, ok := ent.(types.Member); ok {
		g.members[group][member] = struct{}{}
	} else {
		for u := range g.members[ent.(types.Group)] {
			g.members[group][u] = struct{}{}
		}
	}

	return nil
}

func (g *fatGrouping) Leave(ent types.Entity, group types.Group) error {
	if e := g.slim.Leave(ent, group); e != nil {
		return e
	}

	if e := g.rebuildGroups(ent); e != nil {
		return e
	}
	if e := g.rebuildMembers(group); e != nil {
		return e
	}
	return nil
}

func (g *fatGrouping) IsIn(member types.Member, group types.Group) (bool, error) {
	if members, ok := g.members[group]; ok {
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

func (g *fatGrouping) GroupsOf(ent types.Entity) (map[types.Group]struct{}, error) {
	return g.groups[ent], nil
}

func (g *fatGrouping) MembersIn(group types.Group) (map[types.Member]struct{}, error) {
	return g.members[group], nil
}

func (g *fatGrouping) ImmediateGroupsOf(ent types.Entity) (map[types.Group]struct{}, error) {
	return g.slim.ImmediateGroupsOf(ent)
}

func (g *fatGrouping) ImmediateEntitiesIn(group types.Group) (map[types.Entity]struct{}, error) {
	return g.slim.ImmediateEntitiesIn(group)
}

func (g *fatGrouping) RemoveGroup(group types.Group) error {
	delete(g.allGroups, group)
	delete(g.members, group)
	delete(g.groups, group)

	subs, e := g.ImmediateEntitiesIn(group)
	if e != nil {
		return e
	}
	groups, e := g.ImmediateGroupsOf(group)
	if e != nil {
		return e
	}

	if e := g.slim.RemoveGroup(group); e != nil {
		return e
	}

	for ent := range subs {
		if e := g.rebuildGroups(ent); e != nil {
			return e
		}
	}
	for group := range groups {
		if e := g.rebuildMembers(group); e != nil {
			return e
		}
	}

	return nil
}

func (g *fatGrouping) RemoveMember(member types.Member) error {
	delete(g.allMembers, member)
	delete(g.groups, member)

	groups, e := g.ImmediateGroupsOf(member)
	if e != nil {
		return e
	}

	if e := g.slim.RemoveMember(member); e != nil {
		return e
	}

	for group := range groups {
		if e := g.rebuildMembers(group); e != nil {
			return e
		}
	}

	return nil
}

func (g *fatGrouping) rebuildGroups(ent types.Entity) error {
	// rebuild groups for entity
	groups, e := g.ImmediateGroupsOf(ent)
	if e != nil {
		return e
	}
	g.groups[ent] = make(map[types.Group]struct{}, len(groups))
	for group := range groups {
		g.groups[ent][group] = struct{}{}
		for rr := range g.groups[group] {
			g.groups[ent][rr] = struct{}{}
		}
	}

	if group, ok := ent.(types.Group); ok {
		// rebuild groups for all subjects of ent
		// fixme: some entity may be rebuilt more than once
		subs, e := g.ImmediateEntitiesIn(group)
		if e != nil {
			return e
		}
		for ent := range subs {
			if e := g.rebuildGroups(ent); e != nil {
				return e
			}
		}
	}

	return nil
}

func (g *fatGrouping) rebuildMembers(group types.Group) error {
	// rebuild members of group
	subs, e := g.ImmediateEntitiesIn(group)
	if e != nil {
		return e
	}

	g.members[group] = make(map[types.Member]struct{}, len(subs))
	for ent := range subs {
		if member, ok := ent.(types.Member); ok {
			g.members[group][member] = struct{}{}
		} else {
			for member := range g.members[ent.(types.Group)] {
				g.members[group][member] = struct{}{}
			}
		}
	}

	// rebuild members for all groups of group
	// fixme: some group may be rebuilt more than once
	groups, e := g.ImmediateGroupsOf(group)
	if e != nil {
		return e
	}
	for group := range groups {
		if e := g.rebuildMembers(group); e != nil {
			return e
		}
	}

	return nil
}
