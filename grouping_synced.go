package rbac

import "sync"

var _ Grouper = (*syncedGrouper)(nil)

// syncedGrouper is safe in concurrent usages
type syncedGrouper struct {
	g Grouper
	sync.RWMutex
}

func newSyncedGrouper(g Grouper) *syncedGrouper {
	return &syncedGrouper{
		g: g,
	}
}

func (g *syncedGrouper) Join(ent Entity, group Group) error {
	g.Lock()
	defer g.Unlock()
	return g.g.Join(ent, group)
}

// Leave implements Grouper interface
func (g *syncedGrouper) Leave(ent Entity, group Group) error {
	g.Lock()
	defer g.Unlock()
	return g.g.Leave(ent, group)
}

//  IsIn implements Grouper interface
func (g *syncedGrouper) IsIn(individual Individual, group Group) (bool, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.IsIn(individual, group)
}

//  AllGroups implements Grouper interface
func (g *syncedGrouper) AllGroups() (map[Group]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.AllGroups()
}

// AllIndividuals implements Grouper interface
func (g *syncedGrouper) AllIndividuals() (map[Individual]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.AllIndividuals()
}

// GroupsOf implements Grouper interface
func (g *syncedGrouper) GroupsOf(individual Individual) (map[Group]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.GroupsOf(individual)
}

// IndividualsIn implements Grouper interface
func (g *syncedGrouper) IndividualsIn(group Group) (map[Individual]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.IndividualsIn(group)
}

//  ImmediateGroupsOf implements Grouper interface
func (g *syncedGrouper) ImmediateGroupsOf(ent Entity) (map[Group]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.ImmediateGroupsOf(ent)
}

// ImmediateEntitiesIn implements Grouper interface
func (g *syncedGrouper) ImmediateEntitiesIn(group Group) (map[Entity]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.ImmediateEntitiesIn(group)
}

// RemoveGroup implements Grouper interface
func (g *syncedGrouper) RemoveGroup(group Group) error {
	g.Lock()
	defer g.Unlock()
	return g.g.RemoveGroup(group)
}

// RemoveIndividual implements Grouper interface
func (g *syncedGrouper) RemoveIndividual(individual Individual) error {
	g.Lock()
	defer g.Unlock()
	return g.g.RemoveIndividual(individual)
}
