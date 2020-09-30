package grouping

import (
	"fmt"

	"github.com/houz42/rbac/types"
)

var _ grouping = (*slimGrouping)(nil)

// slimGrouping is a simplest implementation of Grouping interface
// it is used as a prototype of concept and baseline for testing
type slimGrouping struct {
	parents  map[types.Entity]map[types.Group]struct{}
	children map[types.Group]map[types.Entity]struct{}
	maxDepth int
}

func newSlimGrouping() *slimGrouping {
	return &slimGrouping{
		parents:  make(map[types.Entity]map[types.Group]struct{}),
		children: make(map[types.Group]map[types.Entity]struct{}),
		maxDepth: 10,
	}
}

// Join implements Grouping interface
func (g *slimGrouping) Join(entity types.Entity, grp types.Group) error {
	if g.parents[entity] == nil {
		g.parents[entity] = make(map[types.Group]struct{}, 1)
	}
	g.parents[entity][grp] = struct{}{}

	if g.children[grp] == nil {
		g.children[grp] = make(map[types.Entity]struct{})
	}
	g.children[grp][entity] = struct{}{}

	return nil
}

// Leave implements Grouping interfaceJ
func (g *slimGrouping) Leave(entity types.Entity, grp types.Group) error {
	if g.parents[entity] == nil {
		return fmt.Errorf("%w: grouping policy: %s -> %s", types.ErrNotFound, entity, grp)
	} else if _, ok := g.parents[entity][grp]; !ok {
		return fmt.Errorf("%w: grouping policy: %s -> %s", types.ErrNotFound, entity, grp)
	}
	delete(g.parents[entity], grp)

	if g.children[grp] == nil {
		return fmt.Errorf("%w: grouping policy: %s -> %s", types.ErrNotFound, grp, entity)
	} else if _, ok := g.children[grp][entity]; !ok {
		return fmt.Errorf("%w: grouping policy: %s -> %s", types.ErrNotFound, grp, entity)
	}
	delete(g.children[grp], entity)

	return nil
}

// IsIn implements Grouping interface
func (g *slimGrouping) IsIn(m types.Member, grp types.Group) (bool, error) {
	groups, err := g.GroupsOf(m)
	if err != nil {
		return false, err
	}

	_, ok := groups[grp]
	return ok, nil
}

// AllGroups implements Grouping interface
func (g *slimGrouping) AllGroups() (map[types.Group]struct{}, error) {
	groups := make(map[types.Group]struct{}, len(g.children))
	for grp := range g.children {
		groups[grp] = struct{}{}
	}
	return groups, nil
}

// AllMembers implements Grouping interface
func (g *slimGrouping) AllMembers() (map[types.Member]struct{}, error) {
	invs := make(map[types.Member]struct{}, len(g.parents))
	for entity := range g.parents {
		if m, ok := entity.(types.Member); ok {
			invs[m] = struct{}{}
		}
	}
	return invs, nil
}

// GroupsOf implements Grouping interface
func (g *slimGrouping) GroupsOf(ent types.Entity) (map[types.Group]struct{}, error) {
	ancients := make(map[types.Group]struct{})

	var query func(entity types.Entity, depth int)
	query = func(entity types.Entity, depth int) {
		if depth > g.maxDepth {
			return
		}
		for r := range g.parents[entity] {
			ancients[r] = struct{}{}
			query(r, depth+1)
		}
	}
	query(ent, 0)

	return ancients, nil
}

// MembersIn implements Grouping interface
func (g *slimGrouping) MembersIn(grp types.Group) (map[types.Member]struct{}, error) {
	children := make(map[types.Member]struct{})

	var query func(grp types.Group, depth int)
	query = func(grp types.Group, depth int) {
		if depth > g.maxDepth {
			return
		}
		for ch := range g.children[grp] {
			if m, ok := ch.(types.Member); ok {
				children[m] = struct{}{}
			} else {
				query(ch.(types.Group), depth+1)
			}
		}
	}
	query(grp, 0)

	return children, nil
}

// ImmediateGroupsOf implements Grouping interface
func (g *slimGrouping) immediateGroupsOf(entity types.Entity) (map[types.Group]struct{}, error) {
	return g.parents[entity], nil
}

// ImmediateEntitiesIn implements Grouping interface
func (g *slimGrouping) immediateEntitiesIn(grp types.Group) (map[types.Entity]struct{}, error) {
	return g.children[grp], nil
}

// RemoveGroup implements Grouping interface
func (g *slimGrouping) RemoveGroup(grp types.Group) error {
	children := g.children[grp]
	parents := g.parents[grp]

	delete(g.children, grp)
	delete(g.parents, grp)

	for ch := range children {
		delete(g.parents[ch], grp)
	}
	for p := range parents {
		delete(g.children[p], grp)
	}

	return nil
}

// RemoveMember implements Grouping interface
func (g *slimGrouping) RemoveMember(m types.Member) error {
	parents := g.parents[m]
	delete(g.parents, m)

	for p := range parents {
		delete(g.children[p], m)
	}
	return nil
}
