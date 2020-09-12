package permission

import (
	"sync"

	"github.com/houz42/rbac/types"
)

var _ types.Permission = (*syncedPermission)(nil)

type syncedPermission struct {
	p types.Permission
	sync.RWMutex
}

// NewSyncedPermission makes the given Permission safe in concurrent usages
func NewSyncedPermission(p types.Permission) *syncedPermission {
	if p == nil {
		p = NewThinPermission()
	}
	return &syncedPermission{p: p}
}

func (p *syncedPermission) Permit(sub types.Subject, obj types.Object, act types.Action) error {
	p.Lock()
	defer p.Unlock()
	return p.p.Permit(sub, obj, act)
}

func (p *syncedPermission) Revoke(sub types.Subject, obj types.Object, act types.Action) error {
	p.Lock()
	defer p.Unlock()
	return p.p.Revoke(sub, obj, act)
}

func (p *syncedPermission) Shall(sub types.Subject, obj types.Object, act types.Action) (bool, error) {
	p.RLock()
	defer p.RUnlock()
	return p.p.Shall(sub, obj, act)
}

func (p *syncedPermission) PermissionsOn(obj types.Object) (map[types.Subject]types.Action, error) {
	p.RLock()
	defer p.RUnlock()
	return p.p.PermissionsOn(obj)
}

func (p *syncedPermission) PermissionsFor(sub types.Subject) (map[types.Object]types.Action, error) {
	p.RLock()
	defer p.RUnlock()
	return p.p.PermissionsFor(sub)
}

func (p *syncedPermission) PermittedActions(sub types.Subject, obj types.Object) (types.Action, error) {
	p.RLock()
	defer p.RUnlock()
	return p.p.PermittedActions(sub, obj)
}
