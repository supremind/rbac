package fake

import (
	"context"
	"sync"

	"github.com/supremind/rbac/types"
)

type permissionPersister struct {
	polices map[types.Subject]map[types.Object]types.Action
	changes chan types.PermissionPolicyChange
	sync.RWMutex
}

// NewPermissionPersister returns a fake permission persister which should not be used in real works
func NewPermissionPersister() *permissionPersister {
	pp := &permissionPersister{
		polices: make(map[types.Subject]map[types.Object]types.Action),
	}

	return pp
}

func (p *permissionPersister) Insert(sub types.Subject, obj types.Object, act types.Action) error {
	p.Lock()
	defer p.Unlock()

	if p.polices[sub] != nil {
		if p.polices[sub][obj] == act {
			return types.ErrAlreadyExists
		}
	} else {
		p.polices[sub] = make(map[types.Object]types.Action)
	}

	p.polices[sub][obj] = act

	if p.changes != nil {
		p.changes <- types.PermissionPolicyChange{
			PermissionPolicy: types.PermissionPolicy{
				Subject: sub,
				Object:  obj,
				Action:  act,
			},
			Method: types.PersistInsert,
		}
	}

	return nil
}

func (p *permissionPersister) Update(sub types.Subject, obj types.Object, act types.Action) error {
	p.Lock()
	defer p.Unlock()

	if p.polices[sub] != nil {
		if p.polices[sub][obj] == act {
			return nil
		}
	} else {
		p.polices[sub] = make(map[types.Object]types.Action)
	}

	p.polices[sub][obj] = act

	if p.changes != nil {
		p.changes <- types.PermissionPolicyChange{
			PermissionPolicy: types.PermissionPolicy{
				Subject: sub,
				Object:  obj,
				Action:  act,
			},
			Method: types.PersistUpdate,
		}
	}

	return nil
}

func (p *permissionPersister) Remove(sub types.Subject, obj types.Object) error {
	p.Lock()
	defer p.Unlock()

	if p.polices[sub] == nil || p.polices[sub][obj] == 0 {
		return types.ErrNotFound
	}

	delete(p.polices[sub], obj)

	if p.changes != nil {
		p.changes <- types.PermissionPolicyChange{
			PermissionPolicy: types.PermissionPolicy{
				Subject: sub,
				Object:  obj,
			},
			Method: types.PersistDelete,
		}
	}

	return nil
}

func (p *permissionPersister) List() ([]types.PermissionPolicy, error) {
	p.RLock()
	defer p.RUnlock()

	polices := make([]types.PermissionPolicy, 0, len(p.polices))
	for sub, perm := range p.polices {
		for obj, act := range perm {
			polices = append(polices, types.PermissionPolicy{
				Subject: sub,
				Object:  obj,
				Action:  act,
			})
		}
	}

	return polices, nil
}

func (p *permissionPersister) Watch(context.Context) (<-chan types.PermissionPolicyChange, error) {
	p.Lock()
	defer p.Unlock()

	p.changes = make(chan types.PermissionPolicyChange)
	return p.changes, nil
}
