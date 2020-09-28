package grouping

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/houz42/rbac/persist/filter"
	"github.com/houz42/rbac/types"
)

// persistedGrouping persists grouping roles of the inner grouping
type persistedGrouping struct {
	persist types.GroupingPersister
	types.Grouping
	log logr.Logger
}

func newPersistedGrouping(ctx context.Context, inner types.Grouping, persist types.GroupingPersister, l logr.Logger) (*persistedGrouping, error) {
	g := &persistedGrouping{
		persist:  filter.NewGroupingPersister(persist),
		Grouping: newSyncedGrouping(inner),
		log:      l,
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
	polices, e := g.persist.List()
	if e != nil {
		return e
	}
	for _, policy := range polices {
		if e := g.Grouping.Join(policy.Entity, policy.Group); e != nil {
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
	switch change.Method {
	case types.PersistInsert:
		return g.Grouping.Join(change.Entity, change.Group)
	case types.PersistDelete:
		if e := g.Grouping.Leave(change.Entity, change.Group); e != nil {
			return e
		}
	}

	return fmt.Errorf("%w: grouping persister changes: %s", types.ErrUnsupportedChange, change.Method)
}

func (g *persistedGrouping) Join(ent types.Entity, group types.Group) error {
	if e := g.persist.Insert(ent, group); e != nil {
		return e
	}
	return g.Grouping.Join(ent, group)
}

func (g *persistedGrouping) Leave(ent types.Entity, group types.Group) error {
	if e := g.persist.Remove(ent, group); e != nil {
		return e
	}

	return g.Grouping.Leave(ent, group)
}

func (g *persistedGrouping) RemoveGroup(group types.Group) error {
	members, e := g.Grouping.ImmediateEntitiesIn(group)
	if e != nil {
		return e
	}
	for member := range members {
		if e := g.Leave(member, group); e != nil {
			return e
		}
	}

	groups, e := g.Grouping.ImmediateGroupsOf(group)
	if e != nil {
		return e
	}
	for super := range groups {
		if e := g.Leave(group, super); e != nil {
			return e
		}
	}

	return g.Grouping.RemoveGroup(group)
}

func (g *persistedGrouping) RemoveMember(m types.Member) error {
	groups, e := g.Grouping.ImmediateGroupsOf(m)
	if e != nil {
		return e
	}
	for group := range groups {
		if e := g.Leave(m, group); e != nil {
			return e
		}
	}

	return g.Grouping.RemoveMember(m)
}
