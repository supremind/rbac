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
	// group => all individuals belongs to it
	individuals map[types.Group]map[types.Individual]struct{}

	allIndividuals map[types.Individual]struct{}
	allGroups      map[types.Group]struct{}
}

// NewFatGrouping creates a new grouping with more cache
func NewFatGrouping() *fatGrouping {
	return &fatGrouping{
		slim:           *NewSlimGrouping(),
		groups:         make(map[types.Entity]map[types.Group]struct{}),
		individuals:    make(map[types.Group]map[types.Individual]struct{}),
		allIndividuals: make(map[types.Individual]struct{}),
		allGroups:      make(map[types.Group]struct{}),
	}
}

func (g *fatGrouping) Join(ent types.Entity, group types.Group) error {
	if e := g.slim.Join(ent, group); e != nil {
		return e
	}

	g.allGroups[group] = struct{}{}
	if individual, ok := ent.(types.Individual); ok {
		g.allIndividuals[individual] = struct{}{}
	}

	if g.groups[ent] == nil {
		g.groups[ent] = make(map[types.Group]struct{})
	}
	g.groups[ent][group] = struct{}{}
	for rr := range g.groups[group] {
		g.groups[ent][rr] = struct{}{}
	}

	if g.individuals[group] == nil {
		g.individuals[group] = make(map[types.Individual]struct{})
	}
	if individual, ok := ent.(types.Individual); ok {
		g.individuals[group][individual] = struct{}{}
	} else {
		for u := range g.individuals[ent.(types.Group)] {
			g.individuals[group][u] = struct{}{}
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
	if e := g.rebuildIndividuals(group); e != nil {
		return e
	}
	return nil
}

func (g *fatGrouping) IsIn(individual types.Individual, group types.Group) (bool, error) {
	if individuals, ok := g.individuals[group]; ok {
		_, ok := individuals[individual]
		return ok, nil
	}
	return false, nil
}

func (g *fatGrouping) AllGroups() (map[types.Group]struct{}, error) {
	return g.allGroups, nil
}

func (g *fatGrouping) AllIndividuals() (map[types.Individual]struct{}, error) {
	return g.allIndividuals, nil
}

func (g *fatGrouping) GroupsOf(ent types.Entity) (map[types.Group]struct{}, error) {
	return g.groups[ent], nil
}

func (g *fatGrouping) IndividualsIn(group types.Group) (map[types.Individual]struct{}, error) {
	return g.individuals[group], nil
}

func (g *fatGrouping) ImmediateGroupsOf(ent types.Entity) (map[types.Group]struct{}, error) {
	return g.slim.ImmediateGroupsOf(ent)
}

func (g *fatGrouping) ImmediateEntitiesIn(group types.Group) (map[types.Entity]struct{}, error) {
	return g.slim.ImmediateEntitiesIn(group)
}

func (g *fatGrouping) RemoveGroup(group types.Group) error {
	delete(g.allGroups, group)
	delete(g.individuals, group)
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
		if e := g.rebuildIndividuals(group); e != nil {
			return e
		}
	}

	return nil
}

func (g *fatGrouping) RemoveIndividual(individual types.Individual) error {
	delete(g.allIndividuals, individual)
	delete(g.groups, individual)

	groups, e := g.ImmediateGroupsOf(individual)
	if e != nil {
		return e
	}

	if e := g.slim.RemoveIndividual(individual); e != nil {
		return e
	}

	for group := range groups {
		if e := g.rebuildIndividuals(group); e != nil {
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

func (g *fatGrouping) rebuildIndividuals(group types.Group) error {
	// rebuild individuals of group
	subs, e := g.ImmediateEntitiesIn(group)
	if e != nil {
		return e
	}

	g.individuals[group] = make(map[types.Individual]struct{}, len(subs))
	for ent := range subs {
		if individual, ok := ent.(types.Individual); ok {
			g.individuals[group][individual] = struct{}{}
		} else {
			for individual := range g.individuals[ent.(types.Group)] {
				g.individuals[group][individual] = struct{}{}
			}
		}
	}

	// rebuild individuals for all groups of group
	// fixme: some group may be rebuilt more than once
	groups, e := g.ImmediateGroupsOf(group)
	if e != nil {
		return e
	}
	for group := range groups {
		if e := g.rebuildIndividuals(group); e != nil {
			return e
		}
	}

	return nil
}
