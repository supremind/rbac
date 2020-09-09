package rbac

import "sync"

var _ Permitter = (*syncedPermitter)(nil)

type syncedPermitter struct {
	p Permitter
	sync.RWMutex
}

func newSyncedPermitter(p Permitter) *syncedPermitter {
	return &syncedPermitter{p: p}
}

func (p *syncedPermitter) Permit(sub Subject, obj Object, act Action) error {
	p.Lock()
	defer p.Unlock()
	return p.p.Permit(sub, obj, act)
}

func (p *syncedPermitter) Revoke(sub Subject, obj Object, act Action) error {
	p.Lock()
	defer p.Unlock()
	return p.p.Revoke(sub, obj, act)
}

func (p *syncedPermitter) Shall(sub Subject, obj Object, act Action) (bool, error) {
	p.RLock()
	defer p.RUnlock()
	return p.p.Shall(sub, obj, act)
}

func (p *syncedPermitter) PermissionsTo(obj Object) (map[Subject]Action, error) {
	p.RLock()
	defer p.RUnlock()
	return p.p.PermissionsTo(obj)
}

func (p *syncedPermitter) PermissionsFor(sub Subject) (map[Object]Action, error) {
	p.RLock()
	defer p.RUnlock()
	return p.p.PermissionsFor(sub)
}

func (p *syncedPermitter) PermittedActions(sub Subject, obj Object) (Action, error) {
	p.RLock()
	defer p.RUnlock()
	return p.p.PermittedActions(sub, obj)
}
