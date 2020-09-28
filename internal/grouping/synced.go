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

	groups, e := g.g.GroupsOf(ent)
	if e != nil {
		return nil, e
	}
	res := make(map[types.Group]struct{}, len(groups))
	for grp := range groups {
		res[grp] = struct{}{}
	}
	return res, nil
}

// MembersIn implements Grouping interface
func (g *syncedGrouping) MembersIn(group types.Group) (map[types.Member]struct{}, error) {
	g.RLock()
	defer g.RUnlock()

	members, e := g.g.MembersIn(group)
	if e != nil {
		return nil, e
	}
	res := make(map[types.Member]struct{}, len(members))
	for mem := range members {
		res[mem] = struct{}{}
	}
	return res, nil
}

//  ImmediateGroupsOf implements Grouping interface
func (g *syncedGrouping) ImmediateGroupsOf(ent types.Entity) (map[types.Group]struct{}, error) {
	g.RLock()
	defer g.RUnlock()

	groups, e := g.g.ImmediateGroupsOf(ent)
	if e != nil {
		return nil, e
	}
	res := make(map[types.Group]struct{}, len(groups))
	for grp := range groups {
		res[grp] = struct{}{}
	}
	return res, nil
}

// ImmediateEntitiesIn implements Grouping interface
func (g *syncedGrouping) ImmediateEntitiesIn(group types.Group) (map[types.Entity]struct{}, error) {
	g.RLock()
	defer g.RUnlock()

	entities, e := g.g.ImmediateEntitiesIn(group)
	if e != nil {
		return nil, e
	}
	res := make(map[types.Entity]struct{}, len(entities))
	for ent := range entities {
		res[ent] = struct{}{}
	}
	return res, nil
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
