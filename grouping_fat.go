package rbac

var _ Grouping = (*fatGrouping)(nil)

// fatGrouping caches more information to speed up querying
// fatGrouping is faster on quering, and slower on removing comprared to slimGrouping
type fatGrouping struct {
	slim slimGrouping // no sense to use another implementation

	// entity => all groups it belongs to
	groups map[Entity]map[Group]struct{}
	// group => all individuals belongs to it
	individuals map[Group]map[Individual]struct{}

	allIndividuals map[Individual]struct{}
	allGroups      map[Group]struct{}
}

func newFatGrouping() *fatGrouping {
	return &fatGrouping{
		slim:           *newSlimGrouping(),
		groups:         make(map[Entity]map[Group]struct{}),
		individuals:    make(map[Group]map[Individual]struct{}),
		allIndividuals: make(map[Individual]struct{}),
		allGroups:      make(map[Group]struct{}),
	}
}

func (g *fatGrouping) Join(ent Entity, group Group) error {
	if e := g.slim.Join(ent, group); e != nil {
		return e
	}

	g.allGroups[group] = struct{}{}
	if individual, ok := ent.(Individual); ok {
		g.allIndividuals[individual] = struct{}{}
	}

	if g.groups[ent] == nil {
		g.groups[ent] = make(map[Group]struct{})
	}
	g.groups[ent][group] = struct{}{}
	for rr := range g.groups[group] {
		g.groups[ent][rr] = struct{}{}
	}

	if g.individuals[group] == nil {
		g.individuals[group] = make(map[Individual]struct{})
	}
	if individual, ok := ent.(Individual); ok {
		g.individuals[group][individual] = struct{}{}
	} else {
		for u := range g.individuals[ent.(Group)] {
			g.individuals[group][u] = struct{}{}
		}
	}

	return nil
}

func (g *fatGrouping) Leave(ent Entity, group Group) error {
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

func (g *fatGrouping) IsIn(individual Individual, group Group) (bool, error) {
	if individuals, ok := g.individuals[group]; ok {
		_, ok := individuals[individual]
		return ok, nil
	}
	return false, nil
}

func (g *fatGrouping) AllGroups() (map[Group]struct{}, error) {
	return g.allGroups, nil
}

func (g *fatGrouping) AllIndividuals() (map[Individual]struct{}, error) {
	return g.allIndividuals, nil
}

func (g *fatGrouping) GroupsOf(ent Entity) (map[Group]struct{}, error) {
	return g.groups[ent], nil
}

func (g *fatGrouping) IndividualsIn(group Group) (map[Individual]struct{}, error) {
	return g.individuals[group], nil
}

func (g *fatGrouping) ImmediateGroupsOf(ent Entity) (map[Group]struct{}, error) {
	return g.slim.ImmediateGroupsOf(ent)
}

func (g *fatGrouping) ImmediateEntitiesIn(group Group) (map[Entity]struct{}, error) {
	return g.slim.ImmediateEntitiesIn(group)
}

func (g *fatGrouping) RemoveGroup(group Group) error {
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

func (g *fatGrouping) RemoveIndividual(individual Individual) error {
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

func (g *fatGrouping) rebuildGroups(ent Entity) error {
	// rebuild groups for entity
	groups, e := g.ImmediateGroupsOf(ent)
	if e != nil {
		return e
	}
	g.groups[ent] = make(map[Group]struct{}, len(groups))
	for group := range groups {
		g.groups[ent][group] = struct{}{}
		for rr := range g.groups[group] {
			g.groups[ent][rr] = struct{}{}
		}
	}

	if group, ok := ent.(Group); ok {
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

func (g *fatGrouping) rebuildIndividuals(group Group) error {
	// rebuild individuals of group
	subs, e := g.ImmediateEntitiesIn(group)
	if e != nil {
		return e
	}

	g.individuals[group] = make(map[Individual]struct{}, len(subs))
	for ent := range subs {
		if individual, ok := ent.(Individual); ok {
			g.individuals[group][individual] = struct{}{}
		} else {
			for individual := range g.individuals[ent.(Group)] {
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
