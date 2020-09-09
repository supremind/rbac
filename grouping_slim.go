package rbac

import "fmt"

var _ Grouper = (*slimGrouper)(nil)

// slimGrouper is a simplest implementation of Grouper interface
// it is used as a prototype of concept and baseline for testing
type slimGrouper struct {
	parents  map[Entity]map[Group]struct{}
	children map[Group]map[Entity]struct{}
	maxDepth int
}

func newSlimGrouper() *slimGrouper {
	return &slimGrouper{
		parents:  make(map[Entity]map[Group]struct{}),
		children: make(map[Group]map[Entity]struct{}),
		maxDepth: 10,
	}
}

// Join implements Grouper interface
func (g *slimGrouper) Join(entity Entity, grp Group) error {
	if g.parents[entity] == nil {
		g.parents[entity] = make(map[Group]struct{}, 1)
	}
	g.parents[entity][grp] = struct{}{}

	if g.children[grp] == nil {
		g.children[grp] = make(map[Entity]struct{})
	}
	g.children[grp][entity] = struct{}{}

	return nil
}

// Leave implements Grouping interfaceJ
func (g *slimGrouper) Leave(entity Entity, grp Group) error {
	if g.parents[entity] == nil {
		return fmt.Errorf("%w: grouping policy: %s -> %s", ErrNotFound, entity, grp)
	} else if _, ok := g.parents[entity][grp]; !ok {
		return fmt.Errorf("%w: grouping policy: %s -> %s", ErrNotFound, entity, grp)
	}
	delete(g.parents[entity], grp)

	if g.children[grp] == nil {
		return fmt.Errorf("%w: grouping policy: %s -> %s", ErrNotFound, grp, entity)
	} else if _, ok := g.children[grp][entity]; !ok {
		return fmt.Errorf("%w: grouping policy: %s -> %s", ErrNotFound, grp, entity)
	}
	delete(g.children[grp], entity)

	return nil
}

// IsIn implements Grouper interface
func (g *slimGrouper) IsIn(ind Individual, grp Group) (bool, error) {
	groups, err := g.GroupsOf(ind)
	if err != nil {
		return false, err
	}

	_, ok := groups[grp]
	return ok, nil
}

// AllGroups implements Grouper interface
func (g *slimGrouper) AllGroups() (map[Group]struct{}, error) {
	groups := make(map[Group]struct{}, len(g.children))
	for grp := range g.children {
		groups[grp] = struct{}{}
	}
	return groups, nil
}

// AllIndividuals implements Grouper interface
func (g *slimGrouper) AllIndividuals() (map[Individual]struct{}, error) {
	invs := make(map[Individual]struct{}, len(g.parents))
	for entity := range g.parents {
		if ind, ok := entity.(Individual); ok {
			invs[ind] = struct{}{}
		}
	}
	return invs, nil
}

// GroupsOf implements Grouper interface
func (g *slimGrouper) GroupsOf(ind Individual) (map[Group]struct{}, error) {
	ancients := make(map[Group]struct{})

	var query func(entity Entity, depth int)
	query = func(entity Entity, depth int) {
		if depth > g.maxDepth {
			return
		}
		for r := range g.parents[entity] {
			ancients[r] = struct{}{}
			query(r, depth+1)
		}
	}
	query(ind, 0)

	return ancients, nil
}

// IndividualsIn implements Grouper interface
func (g *slimGrouper) IndividualsIn(grp Group) (map[Individual]struct{}, error) {
	children := make(map[Individual]struct{})

	var query func(grp Group, depth int)
	query = func(grp Group, depth int) {
		if depth > g.maxDepth {
			return
		}
		for ch := range g.children[grp] {
			if ind, ok := ch.(Individual); ok {
				children[ind] = struct{}{}
			} else {
				query(ch.(Group), depth+1)
			}
		}
	}
	query(grp, 0)

	return children, nil
}

// ImmediateGroupsOf implements Grouper interface
func (g *slimGrouper) ImmediateGroupsOf(entity Entity) (map[Group]struct{}, error) {
	return g.parents[entity], nil
}

// ImmediateEntitiesIn implements Grouper interface
func (g *slimGrouper) ImmediateEntitiesIn(grp Group) (map[Entity]struct{}, error) {
	return g.children[grp], nil
}

// RemoveGroup implements Grouper interface
func (g *slimGrouper) RemoveGroup(grp Group) error {
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

// RemoveIndividual implements Grouper interface
func (g *slimGrouper) RemoveIndividual(ind Individual) error {
	parents := g.parents[ind]
	delete(g.parents, ind)

	for p := range parents {
		delete(g.children[p], ind)
	}
	return nil
}
