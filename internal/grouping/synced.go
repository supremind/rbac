package grouping

import (
	"sync"

	"github.com/houz42/rbac/types"
)

var _ types.Grouping = (*syncedGrouping)(nil)

// syncedGrouping is safe in concurrent usages
type syncedGrouping struct {
	g types.Grouping
	sync.RWMutex
}

// NewSyncedGrouping makes the given Grouping safe in concurrent usages
func NewSyncedGrouping(g types.Grouping) *syncedGrouping {
	if g == nil {
		g = NewFatGrouping()
	}
	return &syncedGrouping{
		g: g,
	}
}

func (g *syncedGrouping) Join(ent types.Entity, group types.Group) error {
	g.Lock()
	defer g.Unlock()
	return g.g.Join(ent, group)
}

// Leave implements Grouping interface
func (g *syncedGrouping) Leave(ent types.Entity, group types.Group) error {
	g.Lock()
	defer g.Unlock()
	return g.g.Leave(ent, group)
}

//  IsIn implements Grouping interface
func (g *syncedGrouping) IsIn(member types.Member, group types.Group) (bool, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.IsIn(member, group)
}

//  AllGroups implements Grouping interface
func (g *syncedGrouping) AllGroups() (map[types.Group]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.AllGroups()
}

// AllIndividuals implements Grouping interface
func (g *syncedGrouping) AllIndividuals() (map[types.Member]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.AllIndividuals()
}

// GroupsOf implements Grouping interface
func (g *syncedGrouping) GroupsOf(ent types.Entity) (map[types.Group]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.GroupsOf(ent)
}

// IndividualsIn implements Grouping interface
func (g *syncedGrouping) IndividualsIn(group types.Group) (map[types.Member]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.IndividualsIn(group)
}

//  ImmediateGroupsOf implements Grouping interface
func (g *syncedGrouping) ImmediateGroupsOf(ent types.Entity) (map[types.Group]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.ImmediateGroupsOf(ent)
}

// ImmediateEntitiesIn implements Grouping interface
func (g *syncedGrouping) ImmediateEntitiesIn(group types.Group) (map[types.Entity]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.ImmediateEntitiesIn(group)
}

// RemoveGroup implements Grouping interface
func (g *syncedGrouping) RemoveGroup(group types.Group) error {
	g.Lock()
	defer g.Unlock()
	return g.g.RemoveGroup(group)
}

// RemoveIndividual implements Grouping interface
func (g *syncedGrouping) RemoveIndividual(member types.Member) error {
	g.Lock()
	defer g.Unlock()
	return g.g.RemoveIndividual(member)
}
