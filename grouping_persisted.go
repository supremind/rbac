package rbac

import (
	"context"
	"fmt"
)

type persistedGrouping struct {
	persist GroupingPersister
	Grouping
}

func newPersistedGrouping(ctx context.Context, inner Grouping, persist GroupingPersister) (*persistedGrouping, error) {
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

func (g *persistedGrouping) coordinateChange(change GroupingPolicyChange) error {
	switch change.Method {
	case PersistInsert:
		return g.Grouping.Join(change.Entity, change.Group)
	case PersistDelete:
		return g.Grouping.Leave(change.Entity, change.Group)
	}

	return fmt.Errorf("%w: grouping persister changes: %s", ErrUnsupportedChange, change.Method)
}

func (g *persistedGrouping) Join(ent Entity, group Group) error {
	if e := g.persist.Insert(ent, group); e != nil {
		return e
	}
	return g.Grouping.Join(ent, group)
}

func (g *persistedGrouping) Leave(ent Entity, group Group) error {
	if e := g.persist.Remove(ent, group); e != nil {
		return e
	}
	return g.Grouping.Leave(ent, group)
}

func (g *persistedGrouping) RemoveGroup(group Group) error {
	if e := g.persist.RemoveByGroup(group); e != nil {
		return e
	}
	return g.RemoveGroup(group)
}

func (g *persistedGrouping) RemoveIndividual(ind Individual) error {
	if e := g.persist.RemoveByIndividual(ind); e != nil {
		return e
	}
	return g.RemoveIndividual(ind)
}
