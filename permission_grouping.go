package rbac

var _ Permission = (*subjectGroupedPermission)(nil)
var _ Permission = (*objectGroupedPermission)(nil)

type subjectGroupedPermission struct {
	sg Grouping
	Permission
}

func newSubjectGroupedPermission(sg Grouping, p Permission) *subjectGroupedPermission {
	return &subjectGroupedPermission{
		sg:         sg,
		Permission: p,
	}
}

func (p *subjectGroupedPermission) Shall(sub Subject, obj Object, act Action) (bool, error) {
	allowed, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return false, e
	}
	if allowed.Includes(act) {
		return true, nil
	}

	groups, e := p.sg.GroupsOf(sub)
	if e != nil {
		return false, e
	}
	perms, e := p.Permission.PermissionsOn(obj)
	if e != nil {
		return false, e
	}

	for group := range groups {
		if perm, ok := perms[group]; ok {
			allowed |= perm
			if allowed.Includes(act) {
				return true, nil
			}
		}
	}

	return false, nil
}

func (p *subjectGroupedPermission) PermissionsFor(sub Subject) (map[Object]Action, error) {
	perms, e := p.Permission.PermissionsFor(sub)
	if e != nil {
		return nil, e
	}
	if perms == nil {
		perms = make(map[Object]Action)
	}

	roles, e := p.sg.GroupsOf(sub)
	if e != nil {
		return nil, e
	}
	for role := range roles {
		rp, e := p.Permission.PermissionsFor(role)
		if e != nil {
			return nil, e
		}
		for obj, act := range rp {
			perms[obj] |= act
		}
	}

	return perms, nil
}

func (p *subjectGroupedPermission) PermittedActions(sub Subject, obj Object) (Action, error) {
	allowed, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return 0, e
	}
	if allowed == allActions {
		return allowed, nil
	}

	groups, e := p.sg.GroupsOf(sub)
	if e != nil {
		return 0, e
	}
	perms, e := p.Permission.PermissionsOn(obj)
	if e != nil {
		return 0, e
	}
	for group := range groups {
		allowed |= perms[group]
		if allowed == allActions {
			return allowed, nil
		}
	}

	return allowed, nil
}

type objectGroupedPermission struct {
	og Grouping
	Permission
}

func newObjectGroupedPermission(og Grouping, p Permission) *objectGroupedPermission {
	return &objectGroupedPermission{
		og:         og,
		Permission: p,
	}
}

func (p *objectGroupedPermission) Shall(sub Subject, obj Object, act Action) (bool, error) {
	allowed, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return false, e
	}
	if allowed.Includes(act) {
		return true, nil
	}

	groups, e := p.og.GroupsOf(obj)
	if e != nil {
		return false, e
	}
	perms, e := p.Permission.PermissionsFor(sub)
	if e != nil {
		return false, e
	}

	for group := range groups {
		if perm, ok := perms[group]; ok {
			allowed |= perm
			if allowed.Includes(act) {
				return true, nil
			}
		}
	}

	return false, nil
}

func (p *objectGroupedPermission) PermissionsOn(obj Object) (map[Subject]Action, error) {
	perms, e := p.Permission.PermissionsOn(obj)
	if e != nil {
		return nil, e
	}
	if perms == nil {
		perms = make(map[Subject]Action)
	}

	cats, e := p.og.GroupsOf(obj)
	if e != nil {
		return nil, e
	}
	for cat := range cats {
		cp, e := p.Permission.PermissionsOn(cat)
		if e != nil {
			return nil, e
		}
		for sub, act := range cp {
			perms[sub] |= act
		}
	}

	return perms, nil
}

func (p *objectGroupedPermission) PermittedActions(sub Subject, obj Object) (Action, error) {
	allowed, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return 0, e
	}
	if allowed == allActions {
		return allowed, nil
	}

	groups, e := p.og.GroupsOf(obj)
	if e != nil {
		return 0, e
	}
	perms, e := p.Permission.PermissionsFor(sub)
	if e != nil {
		return 0, e
	}

	for group := range groups {
		if perm, ok := perms[group]; ok {
			allowed |= perm
			if allowed == allActions {
				return allowed, nil
			}
		}
	}

	return allowed, nil
}

type bothGroupedPermission struct {
	sg Grouping
	og Grouping
	sp Permission
	op Permission
	Permission
}

func newBothGroupedPermission(sg, og Grouping, p Permission) *bothGroupedPermission {
	return &bothGroupedPermission{
		sg:         sg,
		og:         og,
		sp:         newSubjectGroupedPermission(sg, p),
		op:         newObjectGroupedPermission(og, p),
		Permission: p,
	}
}

func (p *bothGroupedPermission) Shall(sub Subject, obj Object, act Action) (bool, error) {
	allowed, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return false, e
	}
	if allowed.Includes(act) {
		return true, nil
	}

	if allow, e := p.sp.Shall(sub, obj, act.Difference(allowed)); e != nil {
		return false, e
	} else if allow {
		return true, e
	}

	if allow, e := p.op.Shall(sub, obj, act.Difference(allowed)); e != nil {
		return false, e
	} else if allow {
		return true, e
	}

	roles, e := p.sg.GroupsOf(sub)
	if e != nil {
		return false, nil
	}
	cats, e := p.og.GroupsOf(obj)
	if e != nil {
		return false, nil
	}
	for role := range roles {
		for cat := range cats {
			perm, e := p.Permission.PermittedActions(role, cat)
			if e != nil {
				return false, nil
			}
			allowed |= perm
			if allowed.Includes(act) {
				return true, nil
			}
		}
	}

	return false, nil
}

func (p *bothGroupedPermission) PermissionsOn(obj Object) (map[Subject]Action, error) {
	return p.op.PermissionsOn(obj)
}

func (p *bothGroupedPermission) PermissionsFor(sub Subject) (map[Object]Action, error) {
	return p.sp.PermissionsFor(sub)
}

func (p *bothGroupedPermission) PermittedActions(sub Subject, obj Object) (Action, error) {
	allowed, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return 0, e
	}
	if allowed == allActions {
		return allowed, nil
	}

	if perm, e := p.sp.PermittedActions(sub, obj); e != nil {
		return 0, e
	} else {
		allowed |= perm
		if allowed == allActions {
			return allowed, nil
		}
	}

	if perm, e := p.op.PermittedActions(sub, obj); e != nil {
		return 0, e
	} else {
		allowed |= perm
		if allowed == allActions {
			return allowed, nil
		}
	}

	roles, e := p.sg.GroupsOf(sub)
	if e != nil {
		return 0, e
	}

	cats, e := p.og.GroupsOf(obj)
	if e != nil {
		return 0, e
	}

	for role := range roles {
		for cat := range cats {
			act, e := p.Permission.PermittedActions(role, cat)
			if e != nil {
				return 0, e
			}

			allowed |= act
			if allowed == allActions {
				return allowed, nil
			}
		}
	}

	return allowed, nil
}
