package rbac

import "context"

type persistedPermission struct {
	persist PermissionPersister
	Permission
}

func newPersistedPermission(ctx context.Context, inner Permission, persist PermissionPersister) (*persistedPermission, error) {
	p := &persistedPermission{
		persist:    persist,
		Permission: inner,
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
					// todo: log and notify
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

func (p *persistedPermission) coordinateChange(change PermissionChange) error {
	switch change.Method {
	case PersistInsert:
		return p.Permission.Permit(change.Subject, change.Object, change.Action)

	case PersistUpdate:
		prev, e := p.Permission.PermittedActions(change.Subject, change.Object)
		if e != nil {
			return e
		}
		if minus := prev.Difference(change.Action); minus > 0 {
			return p.Permission.Revoke(change.Subject, change.Object, minus)
		}
		if plus := change.Action.Difference(prev); prev > 0 {
			return p.Permission.Permit(change.Subject, change.Object, plus)
		}

	case PersistDelete:
		prev, e := p.Permission.PermittedActions(change.Subject, change.Object)
		if e != nil {
			return e
		}
		if prev > 0 {
			return p.Permission.Revoke(change.Subject, change.Object, prev)
		}
	}

	return nil
}

// Permit subject to perform action on object
func (p *persistedPermission) Permit(sub Subject, obj Object, act Action) error {
	before, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return e
	}
	after := act | before

	if e := p.persist.Upsert(sub, obj, after); e != nil {
		return e
	}

	return p.Permission.Permit(sub, obj, act)
}

// Revoke permission for subject to perform action on object
func (p *persistedPermission) Revoke(sub Subject, obj Object, act Action) error {
	before, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return e
	}
	after := before.Difference(act)

	if after > 0 {
		if e := p.persist.Upsert(sub, obj, after); e != nil {
			return e
		}
	} else {
		if e := p.persist.Remove(sub, obj); e != nil {
			return e
		}
	}

	return p.Permission.Revoke(sub, obj, act)
}
