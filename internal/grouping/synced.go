package grouping

import (
	"sync"

	. "github.com/supremind/rbac/types"
)

var _ Grouping = (*syncedGrouping)(nil)

// syncedGrouping is safe in concurrent usages
type syncedGrouping struct {
	g Grouping
	sync.RWMutex
}

func NewSyncedGrouping(g Grouping) *syncedGrouping {
	return &syncedGrouping{
		g: g,
	}
}

func (g *syncedGrouping) Join(ent Entity, group Group) error {
	g.Lock()
	defer g.Unlock()
	return g.g.Join(ent, group)
}

// Leave implements Grouping interface
func (g *syncedGrouping) Leave(ent Entity, group Group) error {
	g.Lock()
	defer g.Unlock()
	return g.g.Leave(ent, group)
}

//  IsIn implements Grouping interface
func (g *syncedGrouping) IsIn(individual Individual, group Group) (bool, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.IsIn(individual, group)
}

//  AllGroups implements Grouping interface
func (g *syncedGrouping) AllGroups() (map[Group]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.AllGroups()
}

// AllIndividuals implements Grouping interface
func (g *syncedGrouping) AllIndividuals() (map[Individual]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.AllIndividuals()
}

// GroupsOf implements Grouping interface
func (g *syncedGrouping) GroupsOf(ent Entity) (map[Group]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.GroupsOf(ent)
}

// IndividualsIn implements Grouping interface
func (g *syncedGrouping) IndividualsIn(group Group) (map[Individual]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.IndividualsIn(group)
}

//  ImmediateGroupsOf implements Grouping interface
func (g *syncedGrouping) ImmediateGroupsOf(ent Entity) (map[Group]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.ImmediateGroupsOf(ent)
}

// ImmediateEntitiesIn implements Grouping interface
func (g *syncedGrouping) ImmediateEntitiesIn(group Group) (map[Entity]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.ImmediateEntitiesIn(group)
}

// RemoveGroup implements Grouping interface
func (g *syncedGrouping) RemoveGroup(group Group) error {
	g.Lock()
	defer g.Unlock()
	return g.g.RemoveGroup(group)
}

// RemoveIndividual implements Grouping interface
func (g *syncedGrouping) RemoveIndividual(individual Individual) error {
	g.Lock()
	defer g.Unlock()
	return g.g.RemoveIndividual(individual)
}
