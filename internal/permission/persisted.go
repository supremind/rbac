package permission

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/supremind/rbac/internal/persist/filter"
	"github.com/supremind/rbac/types"
)

// persistedPermission persists the permission polices with given persister, and makes sure it is synced
type persistedPermission struct {
	persist types.PermissionPersister
	types.Permission
	log logr.Logger
}

func newPersistedPermission(ctx context.Context, inner types.Permission, persist types.PermissionPersister, l logr.Logger) (*persistedPermission, error) {
	p := &persistedPermission{
		persist:    filter.NewPermissionPersister(persist),
		Permission: newSyncedPermission(inner),
		log:        l,
	}

	if e := p.loadPersisted(); e != nil {
		return nil, e
	}
	if e := p.startWatching(ctx); e != nil {
		return nil, e
	}

	return p, nil
}

func (p *persistedPermission) loadPersisted() error {
	p.log.V(4).Info("load persisted changes")
	polices, e := p.persist.List()
	if e != nil {
		return e
	}
	for _, policy := range polices {
		if e := p.Permission.Permit(policy.Subject, policy.Object, policy.Action); e != nil {
			return e
		}
	}

	return nil
}

func (p *persistedPermission) startWatching(ctx context.Context) error {
	changes, e := p.persist.Watch(ctx)
	if e != nil {
		return e
	}

	go func() {
		for {
			select {
			case change := <-changes:
				if e := p.coordinateChange(change); e != nil {
					p.log.Error(e, "coordinate permission changes")
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

func (p *persistedPermission) coordinateChange(change types.PermissionPolicyChange) error {
	p.log.V(4).Info("coordinate permission changes", "change", change)

	switch change.Method {
	case types.PersistInsert, types.PersistUpdate:
		prev, e := p.Permission.PermittedActions(change.Subject, change.Object)
		if e != nil {
			return e
		}
		if prev.Includes(change.Action) {
			return p.Permission.Revoke(change.Subject, change.Object, prev.Difference(change.Action))
		}
		return p.Permission.Permit(change.Subject, change.Object, change.Action.Difference(prev))

	case types.PersistDelete:
		prev, e := p.Permission.PermittedActions(change.Subject, change.Object)
		if e != nil {
			return e
		}
		if prev > 0 {
			return p.Permission.Revoke(change.Subject, change.Object, prev)
		}
		return nil
	}

	return fmt.Errorf("%w: permission persister changes: %s", types.ErrUnsupportedChange, change.Method)
}

// Permit subject to perform action on object
func (p *persistedPermission) Permit(sub types.Subject, obj types.Object, act types.Action) error {
	p.log.V(4).Info("permit", "subject", sub, "object", obj, "action", act)

	before, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return e
	}

	if before > 0 {
		if e := p.persist.Update(sub, obj, act|before); e != nil {
			return e
		}
	} else {
		if e := p.persist.Insert(sub, obj, act); e != nil {
			return e
		}
	}

	return p.Permission.Permit(sub, obj, act)
}

// Revoke permission for subject to perform action on object
func (p *persistedPermission) Revoke(sub types.Subject, obj types.Object, act types.Action) error {
	p.log.V(4).Info("revoke", "subject", sub, "object", obj, "action", act)

	before, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return e
	}
	after := before.Difference(act)

	if after > 0 {
		if e := p.persist.Update(sub, obj, after); e != nil {
			return e
		}
	} else {
		if e := p.persist.Remove(sub, obj); e != nil {
			return e
		}
	}

	return p.Permission.Revoke(sub, obj, act)
}
