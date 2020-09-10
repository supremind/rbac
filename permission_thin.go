package rbac

import "fmt"

var _ Permission = (*thinPermission)(nil)

// thinPermission knows only direct subject-object-actions relationships
type thinPermission struct {
	bySubject map[Subject]map[Object]Action
	byObject  map[Object]map[Subject]Action
}

func newThinPermission() *thinPermission {
	return &thinPermission{
		bySubject: make(map[Subject]map[Object]Action),
		byObject:  make(map[Object]map[Subject]Action),
	}
}

func (p *thinPermission) Permit(sub Subject, obj Object, act Action) error {
	if _, ok := p.bySubject[sub]; !ok {
		p.bySubject[sub] = make(map[Object]Action)
	}
	p.bySubject[sub][obj] |= act

	if _, ok := p.byObject[obj]; !ok {
		p.byObject[obj] = make(map[Subject]Action)
	}
	p.byObject[obj][sub] |= act

	return nil
}

func (p *thinPermission) Revoke(sub Subject, obj Object, act Action) error {
	if _, ok := p.bySubject[sub]; !ok {
		return fmt.Errorf("%w: permission %s -[%s]-> %s", ErrNotFound, sub, obj, act)
	}
	p.bySubject[sub][obj] &= ^act
	if p.bySubject[sub][obj] == 0 {
		delete(p.bySubject[sub], obj)
	}

	if _, ok := p.byObject[obj]; !ok {
		return fmt.Errorf("%w: permission %s -[%s]-> %s", ErrNotFound, sub, obj, act)
	}
	p.byObject[obj][sub] &= ^act
	if p.byObject[obj][sub] == 0 {
		delete(p.byObject[obj], sub)
	}

	return nil
}

func (p *thinPermission) Shall(sub Subject, obj Object, act Action) (bool, error) {
	if objs, ok := p.bySubject[sub]; ok {
		if acts, ok := objs[obj]; ok {
			return acts.Includes(act), nil
		}
	}

	return false, nil
}

func (p *thinPermission) PermissionsOn(obj Object) (map[Subject]Action, error) {
	return p.byObject[obj], nil
}

func (p *thinPermission) PermissionsFor(sub Subject) (map[Object]Action, error) {
	return p.bySubject[sub], nil
}

func (p *thinPermission) PermittedActions(sub Subject, obj Object) (Action, error) {
	if _, ok := p.bySubject[sub]; !ok {
		return 0, nil
	}
	return p.bySubject[sub][obj], nil
}
