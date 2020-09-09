package rbac

var _ Permission = (*subjectGroupedPermission)(nil)
var _ Permission = (*objectGroupedPermission)(nil)

type subjectGroupedPermission struct {
	sg Grouping
	Permission
}

func newSubjectGroupedPermission(sg Grouping) *subjectGroupedPermission {
	return &subjectGroupedPermission{
		sg:         sg,
		Permission: newThinPermission(),
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
	perms, e := p.Permission.PermissionsTo(obj)
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

func (p *subjectGroupedPermission) PermittedActions(sub Subject, obj Object) (Action, error) {
	allowed, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return 0, e
	}
	groups, e := p.sg.GroupsOf(sub)
	if e != nil {
		return 0, e
	}
	perms, e := p.Permission.PermissionsTo(obj)
	if e != nil {
		return 0, e
	}
	for group := range groups {
		allowed |= perms[group]
	}

	return allowed, nil
}

type objectGroupedPermission struct {
	og Grouping
	Permission
}

func newObjectGroupedPermission(og Grouping) *objectGroupedPermission {
	return &objectGroupedPermission{
		og:         og,
		Permission: newThinPermission(),
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
		allowed |= perms[group]
		if allowed.Includes(act) {
			return true, nil
		}
	}

	return false, nil
}

func (p *objectGroupedPermission) PermittedActions(sub Subject, obj Object) (Action, error) {
	allowed, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return 0, e
	}
	groups, e := p.og.GroupsOf(sub)
	if e != nil {
		return 0, e
	}
	perms, e := p.Permission.PermissionsFor(sub)
	if e != nil {
		return 0, e
	}
	for group := range groups {
		allowed |= perms[group]
	}

	return allowed, nil
}

type bothGroupedPermission struct {
	sg Grouping
	og Grouping
	Permission
}

func newBothGroupedPermission(sg, og Grouping) *bothGroupedPermission {
	return &bothGroupedPermission{
		sg:         sg,
		og:         og,
		Permission: newThinPermission(),
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

	groups, e := p.sg.GroupsOf(sub)
	if e != nil {
		return false, e
	}
	perms, e := p.Permission.PermissionsTo(obj)
	if e != nil {
		return false, e
	}

	for group := range groups {
		allowed |= perms[group]
		if allowed.Includes(act) {
			return true, nil
		}
	}

	return false, nil
}

func (p *bothGroupedPermission) PermittedActions(sub Subject, obj Object) (Action, error) {
	allowed, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return 0, e
	}

	roles, e := p.sg.GroupsOf(sub)
	if e != nil {
		return 0, e
	}
	subjects := make(map[Subject]struct{}, len(roles)+1)
	subjects[sub] = struct{}{}
	for role := range roles {
		subjects[role] = struct{}{}
	}

	cats, e := p.og.GroupsOf(obj)
	if e != nil {
		return 0, e
	}
	objects := make(map[Object]struct{}, len(cats)+1)
	objects[obj] = struct{}{}
	for cat := range cats {
		objects[cat] = struct{}{}
	}

	for sub := range subjects {
		for obj := range objects {
			act, e := p.Permission.PermittedActions(sub, obj)
			if e != nil {
				return 0, e
			}

			allowed |= act
			if allowed == ReadWriteExec {
				return allowed, nil
			}
		}
	}

	return allowed, nil
}
