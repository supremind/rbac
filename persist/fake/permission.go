package fake

import (
	"context"

	"github.com/supremind/rbac"
)

type PermissionPersister struct {
	polices map[rbac.Subject]map[rbac.Object]rbac.Action
	changes chan rbac.PermissionChange
}

func NewPermissionPersister(ctx context.Context, initPolices ...rbac.PermissionPolicy) *PermissionPersister {
	pp := &PermissionPersister{
		polices: make(map[rbac.Subject]map[rbac.Object]rbac.Action),
		changes: make(chan rbac.PermissionChange),
	}

	for _, policy := range initPolices {
		if pp.polices[policy.Subject] == nil {
			pp.polices[policy.Subject] = make(map[rbac.Object]rbac.Action)
		}
		pp.polices[policy.Subject][policy.Object] |= policy.Action
	}

	go func() {
		<-ctx.Done()
		close(pp.changes)
	}()

	return pp
}

func (p *PermissionPersister) Upsert(sub rbac.Subject, obj rbac.Object, act rbac.Action) error {
	if p.polices[sub] != nil {
		if p.polices[sub][obj] == act {
			return nil
		}
	} else {
		p.polices[sub] = make(map[rbac.Object]rbac.Action)
	}

	p.polices[sub][obj] = act
	p.changes <- rbac.PermissionChange{
		PermissionPolicy: rbac.PermissionPolicy{
			Subject: sub,
			Object:  obj,
			Action:  act,
		},
		Method: rbac.PersistInsert,
	}
	return nil
}

func (p *PermissionPersister) Remove(sub rbac.Subject, obj rbac.Object) error {
	if p.polices[sub] == nil || p.polices[sub][obj] == 0 {
		return nil
	}

	delete(p.polices[sub], obj)
	p.changes <- rbac.PermissionChange{
		PermissionPolicy: rbac.PermissionPolicy{
			Subject: sub,
			Object:  obj,
		},
		Method: rbac.PersistDelete,
	}
	return nil
}

func (p *PermissionPersister) List() ([]rbac.PermissionPolicy, error) {
	polices := make([]rbac.PermissionPolicy, 0, len(p.polices))
	for sub, perm := range p.polices {
		for obj, act := range perm {
			polices = append(polices, rbac.PermissionPolicy{
				Subject: sub,
				Object:  obj,
				Action:  act,
			})
		}
	}

	return polices, nil
}

func (p *PermissionPersister) Watch(context.Context) (<-chan rbac.PermissionChange, error) {
	return p.changes, nil
}
