package fake

import (
	"context"

	"github.com/houz42/rbac/types"
)

type permissionPersister struct {
	polices map[types.Subject]map[types.Object]types.Action
	changes chan types.PermissionPolicyChange
}

// NewPermissionPersister returns a fake permission persister which should not be used in real works
func NewPermissionPersister(ctx context.Context) *permissionPersister {
	pp := &permissionPersister{
		polices: make(map[types.Subject]map[types.Object]types.Action),
		changes: make(chan types.PermissionPolicyChange),
	}

	go func() {
		<-ctx.Done()
		close(pp.changes)
	}()

	return pp
}

func (p *permissionPersister) Insert(sub types.Subject, obj types.Object, act types.Action) error {
	if p.polices[sub] != nil {
		if p.polices[sub][obj] == act {
			return nil
		}
	} else {
		p.polices[sub] = make(map[types.Object]types.Action)
	}

	p.polices[sub][obj] = act
	p.changes <- types.PermissionPolicyChange{
		PermissionPolicy: types.PermissionPolicy{
			Subject: sub,
			Object:  obj,
			Action:  act,
		},
		Method: types.PersistInsert,
	}
	return nil
}

func (p *permissionPersister) Update(sub types.Subject, obj types.Object, act types.Action) error {
	if p.polices[sub] != nil {
		if p.polices[sub][obj] == act {
			return nil
		}
	} else {
		p.polices[sub] = make(map[types.Object]types.Action)
	}

	p.polices[sub][obj] = act
	p.changes <- types.PermissionPolicyChange{
		PermissionPolicy: types.PermissionPolicy{
			Subject: sub,
			Object:  obj,
			Action:  act,
		},
		Method: types.PersistUpdate,
	}
	return nil
}

func (p *permissionPersister) Remove(sub types.Subject, obj types.Object) error {
	if p.polices[sub] == nil || p.polices[sub][obj] == 0 {
		return nil
	}

	delete(p.polices[sub], obj)
	p.changes <- types.PermissionPolicyChange{
		PermissionPolicy: types.PermissionPolicy{
			Subject: sub,
			Object:  obj,
		},
		Method: types.PersistDelete,
	}
	return nil
}

func (p *permissionPersister) List() ([]types.PermissionPolicy, error) {
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
	return p.changes, nil
}
