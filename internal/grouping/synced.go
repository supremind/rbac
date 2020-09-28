package grouping

import (
	"sync"

	"github.com/houz42/rbac/types"
)

var _ types.Grouping = (*syncedGrouping)(nil)

// syncedGrouping makes the inner grouping be safe in concurrent usages
type syncedGrouping struct {
	g types.Grouping
	sync.RWMutex
}

func newSyncedGrouping(g types.Grouping) *syncedGrouping {
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

// AllMembers implements Grouping interface
func (g *syncedGrouping) AllMembers() (map[types.Member]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.AllMembers()
}

// GroupsOf implements Grouping interface
func (g *syncedGrouping) GroupsOf(ent types.Entity) (map[types.Group]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.GroupsOf(ent)
}

// MembersIn implements Grouping interface
func (g *syncedGrouping) MembersIn(group types.Group) (map[types.Member]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.MembersIn(group)
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

// RemoveMember implements Grouping interface
func (g *syncedGrouping) RemoveMember(member types.Member) error {
	g.Lock()
	defer g.Unlock()
	return g.g.RemoveMember(member)
}
