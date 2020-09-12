package permission

import (
	"sync"

	. "github.com/houz42/rbac/types"
)

var _ Permission = (*syncedPermission)(nil)

type syncedPermission struct {
	p Permission
	sync.RWMutex
}

func NewSyncedPermission(p Permission) *syncedPermission {
	if p == nil {
		p = NewThinPermission()
	}
	return &syncedPermission{p: p}
}

func (p *syncedPermission) Permit(sub Subject, obj Object, act Action) error {
	p.Lock()
	defer p.Unlock()
	return p.p.Permit(sub, obj, act)
}

func (p *syncedPermission) Revoke(sub Subject, obj Object, act Action) error {
	p.Lock()
	defer p.Unlock()
	return p.p.Revoke(sub, obj, act)
}

func (p *syncedPermission) Shall(sub Subject, obj Object, act Action) (bool, error) {
	p.RLock()
	defer p.RUnlock()
	return p.p.Shall(sub, obj, act)
}

func (p *syncedPermission) PermissionsOn(obj Object) (map[Subject]Action, error) {
	p.RLock()
	defer p.RUnlock()
	return p.p.PermissionsOn(obj)
}

func (p *syncedPermission) PermissionsFor(sub Subject) (map[Object]Action, error) {
	p.RLock()
	defer p.RUnlock()
	return p.p.PermissionsFor(sub)
}

func (p *syncedPermission) PermittedActions(sub Subject, obj Object) (Action, error) {
	p.RLock()
	defer p.RUnlock()
	return p.p.PermittedActions(sub, obj)
}
