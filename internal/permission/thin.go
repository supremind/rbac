package permission

import (
	"fmt"

	"github.com/supremind/rbac/types"
)

var _ types.Permission = (*thinPermission)(nil)

// thinPermission knows only direct subject-object-actions relationships
type thinPermission struct {
	bySubject map[types.Subject]map[types.Object]types.Action
	byObject  map[types.Object]map[types.Subject]types.Action
}

func newThinPermission() *thinPermission {
	return &thinPermission{
		bySubject: make(map[types.Subject]map[types.Object]types.Action),
		byObject:  make(map[types.Object]map[types.Subject]types.Action),
	}
}

func (p *thinPermission) Permit(sub types.Subject, obj types.Object, act types.Action) error {
	if _, ok := p.bySubject[sub]; !ok {
		p.bySubject[sub] = make(map[types.Object]types.Action)
	}
	p.bySubject[sub][obj] |= act

	if _, ok := p.byObject[obj]; !ok {
		p.byObject[obj] = make(map[types.Subject]types.Action)
	}
	p.byObject[obj][sub] |= act

	return nil
}

func (p *thinPermission) Revoke(sub types.Subject, obj types.Object, act types.Action) error {
	if _, ok := p.bySubject[sub]; !ok {
		return fmt.Errorf("%w: permission %s -[%s]-> %s", types.ErrNotFound, sub, obj, act)
	}
	p.bySubject[sub][obj] &= ^act
	if p.bySubject[sub][obj] == 0 {
		delete(p.bySubject[sub], obj)
	}

	if _, ok := p.byObject[obj]; !ok {
		return fmt.Errorf("%w: permission %s -[%s]-> %s", types.ErrNotFound, sub, obj, act)
	}
	p.byObject[obj][sub] &= ^act
	if p.byObject[obj][sub] == 0 {
		delete(p.byObject[obj], sub)
	}

	return nil
}

func (p *thinPermission) Shall(sub types.Subject, obj types.Object, act types.Action) (bool, error) {
	if objs, ok := p.bySubject[sub]; ok {
		if acts, ok := objs[obj]; ok {
			return acts.Includes(act), nil
		}
	}

	return false, nil
}

func (p *thinPermission) PermissionsOn(obj types.Object) (map[types.Subject]types.Action, error) {
	return p.byObject[obj], nil
}

func (p *thinPermission) PermissionsFor(sub types.Subject) (map[types.Object]types.Action, error) {
	return p.bySubject[sub], nil
}

func (p *thinPermission) PermittedActions(sub types.Subject, obj types.Object) (types.Action, error) {
	if _, ok := p.bySubject[sub]; !ok {
		return 0, nil
	}
	return p.bySubject[sub][obj], nil
}
