package grouping

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/houz42/rbac/internal/persist/filter"
	"github.com/houz42/rbac/types"
)

var _ grouping = (*persistedGrouping)(nil)

// persistedGrouping persists grouping roles of the inner grouping
type persistedGrouping struct {
	persist types.GroupingPersister
	grouping
	log logr.Logger
}

func newPersistedGrouping(ctx context.Context, persist types.GroupingPersister, l logr.Logger) (*persistedGrouping, error) {
	g := &persistedGrouping{
		persist:  filter.NewGroupingPersister(persist),
		log:      l,
		grouping: newSyncedGrouping(newFatGrouping()),
	}
	if e := g.loadPersisted(); e != nil {
		return nil, e
	}
	if e := g.startWatching(ctx); e != nil {
		return nil, e
	}

	return g, nil
}

func (g *persistedGrouping) loadPersisted() error {
	g.log.V(4).Info("load persisted polices")

	polices, e := g.persist.List()
	if e != nil {
		return e
	}
	for _, policy := range polices {
		if e := g.grouping.Join(policy.Entity, policy.Group); e != nil {
			return e
		}
	}
	return nil
}

func (g *persistedGrouping) startWatching(ctx context.Context) error {
	changes, e := g.persist.Watch(ctx)
	if e != nil {
		return e
	}

	go func() {
		for {
			select {
			case change := <-changes:
				if e := g.coordinateChange(change); e != nil {
					g.log.Error(e, "coordinate grouping changes")
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

func (g *persistedGrouping) coordinateChange(change types.GroupingPolicyChange) error {
	g.log.V(4).Info("coordinate grouping changes", "change", change)

	switch change.Method {
	case types.PersistInsert:
		return g.grouping.Join(change.Entity, change.Group)
	case types.PersistDelete:
		return g.grouping.Leave(change.Entity, change.Group)
	}

	return fmt.Errorf("%w: grouping persister changes: %s", types.ErrUnsupportedChange, change.Method)
}

func (g *persistedGrouping) Join(ent types.Entity, group types.Group) error {
	g.log.V(4).Info("join", "member", ent, "group", group)

	if e := g.persist.Insert(ent, group); e != nil {
		return e
	}
	return g.grouping.Join(ent, group)
}

func (g *persistedGrouping) Leave(ent types.Entity, group types.Group) error {
	g.log.V(4).Info("leave", "member", ent, "group", group)

	if e := g.persist.Remove(ent, group); e != nil {
		return e
	}

	return g.grouping.Leave(ent, group)
}

func (g *persistedGrouping) RemoveGroup(group types.Group) error {
	g.log.V(4).Info("remove group", "group", group)

	members, e := g.grouping.immediateEntitiesIn(group)
	if e != nil {
		return e
	}
	for member := range members {
		if e := g.persist.Remove(member, group); e != nil {
			return e
		}
	}

	groups, e := g.grouping.immediateGroupsOf(group)
	if e != nil {
		return e
	}
	for super := range groups {
		if e := g.persist.Remove(group, super); e != nil {
			return e
		}
	}

	return g.grouping.RemoveGroup(group)
}

func (g *persistedGrouping) RemoveMember(m types.Member) error {
	g.log.V(4).Info("remove member", "member", m)

	groups, e := g.grouping.immediateGroupsOf(m)
	if e != nil {
		return e
	}
	for group := range groups {
		if e := g.persist.Remove(m, group); e != nil {
			return e
		}
	}

	return g.grouping.RemoveMember(m)
}
