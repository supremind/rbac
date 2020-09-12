package grouping

import (
	"context"
	"errors"
	"fmt"

	"github.com/houz42/rbac/types"
)

type persistedGrouping struct {
	persist types.GroupingPersister
	types.Grouping
}

// NewPersistedGrouping create a persisted types.Grouping based on given inner types.Grouping,
// the inner types.Grouping must be synced
func NewPersistedGrouping(ctx context.Context, inner types.Grouping, persist types.GroupingPersister) (*persistedGrouping, error) {
	if inner == nil {
		inner = NewFatGrouping()
	}
	inner = NewSyncedGrouping(inner)
	g := &persistedGrouping{persist: persist, Grouping: inner}
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
					// todo
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
			if errors.Is(e, types.ErrNotFound) {
				return nil
			}
			return nil
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
	if e := g.persist.RemoveByGroup(group); e != nil {
		return e
	}
	return g.Grouping.RemoveGroup(group)
}

func (g *persistedGrouping) RemoveIndividual(ind types.Individual) error {
	if e := g.persist.RemoveByIndividual(ind); e != nil {
		return e
	}
	return g.Grouping.RemoveIndividual(ind)
}
