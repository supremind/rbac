package authorizer

import (
	"github.com/houz42/rbac/internal/permission"
	"github.com/houz42/rbac/types"
)

var _ subjectGroupedPermissioner = (*subjectGroupedPermission)(nil)
var _ objectGroupedPermissioner = (*objectGroupedPermission)(nil)
var _ bothGroupedPermissioner = (*bothGroupedPermission)(nil)

type subjectGroupedPermissioner interface {
	types.Permission
	directPermissionsFor(types.Subject) (map[types.Object]types.Action, error)
}

type objectGroupedPermissioner interface {
	types.Permission
	directPermissionsOn(types.Object) (map[types.Subject]types.Action, error)
}

type bothGroupedPermissioner interface {
	subjectGroupedPermissioner
	objectGroupedPermissioner
}

type subjectGroupedPermission struct {
	sg types.Grouping
	types.Permission
}

// NewSubjectGroupedPermission makes the permission know user-role relationships and make decisions with them
func NewSubjectGroupedPermission(sg types.Grouping, p types.Permission) *subjectGroupedPermission {
	if p == nil {
		p = permission.NewThinPermission()
	}
	return &subjectGroupedPermission{
		sg:         sg,
		Permission: p,
	}
}

func (p *subjectGroupedPermission) Shall(sub types.Subject, obj types.Object, act types.Action) (bool, error) {
	allowed, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return false, e
	}
	if allowed.Includes(act) {
		return true, nil
	}

	roles, e := p.sg.GroupsOf(sub)
	if e != nil {
		return false, e
	}
	perms, e := p.Permission.PermissionsOn(obj)
	if e != nil {
		return false, e
	}

	for role := range roles {
		if perm, ok := perms[role.(types.Role)]; ok {
			allowed |= perm
			if allowed.Includes(act) {
				return true, nil
			}
		}
	}

	return false, nil
}

func (p *subjectGroupedPermission) PermissionsFor(sub types.Subject) (map[types.Object]types.Action, error) {
	perms, e := p.Permission.PermissionsFor(sub)
	if e != nil {
		return nil, e
	}
	if perms == nil {
		perms = make(map[types.Object]types.Action)
	}

	roles, e := p.sg.GroupsOf(sub)
	if e != nil {
		return nil, e
	}
	for role := range roles {
		rp, e := p.Permission.PermissionsFor(role.(types.Role))
		if e != nil {
			return nil, e
		}
		for obj, act := range rp {
			perms[obj] |= act
		}
	}

	return perms, nil
}

func (p *subjectGroupedPermission) PermittedActions(sub types.Subject, obj types.Object) (types.Action, error) {
	allowed, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return 0, e
	}
	if allowed == types.AllActions {
		return allowed, nil
	}

	roles, e := p.sg.GroupsOf(sub)
	if e != nil {
		return 0, e
	}
	perms, e := p.Permission.PermissionsOn(obj)
	if e != nil {
		return 0, e
	}
	for role := range roles {
		allowed |= perms[role.(types.Role)]
		if allowed == types.AllActions {
			return allowed, nil
		}
	}

	return allowed, nil
}

func (p *subjectGroupedPermission) directPermissionsFor(sub types.Subject) (map[types.Object]types.Action, error) {
	return p.Permission.PermissionsFor(sub)
}

type objectGroupedPermission struct {
	og types.Grouping
	types.Permission
}

// NewObjectGroupedPermission makes the permission knows article-category relationships and make decions with them
func NewObjectGroupedPermission(og types.Grouping, p types.Permission) *objectGroupedPermission {
	if p == nil {
		p = permission.NewThinPermission()
	}
	return &objectGroupedPermission{
		og:         og,
		Permission: p,
	}
}

func (p *objectGroupedPermission) Shall(sub types.Subject, obj types.Object, act types.Action) (bool, error) {
	allowed, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return false, e
	}
	if allowed.Includes(act) {
		return true, nil
	}

	categories, e := p.og.GroupsOf(obj)
	if e != nil {
		return false, e
	}
	perms, e := p.Permission.PermissionsFor(sub)
	if e != nil {
		return false, e
	}

	for category := range categories {
		if perm, ok := perms[category.(types.Category)]; ok {
			allowed |= perm
			if allowed.Includes(act) {
				return true, nil
			}
		}
	}

	return false, nil
}

func (p *objectGroupedPermission) PermissionsOn(obj types.Object) (map[types.Subject]types.Action, error) {
	perms, e := p.Permission.PermissionsOn(obj)
	if e != nil {
		return nil, e
	}
	if perms == nil {
		perms = make(map[types.Subject]types.Action)
	}

	cats, e := p.og.GroupsOf(obj)
	if e != nil {
		return nil, e
	}
	for cat := range cats {
		cp, e := p.Permission.PermissionsOn(cat.(types.Category))
		if e != nil {
			return nil, e
		}
		for sub, act := range cp {
			perms[sub] |= act
		}
	}

	return perms, nil
}

func (p *objectGroupedPermission) PermittedActions(sub types.Subject, obj types.Object) (types.Action, error) {
	allowed, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return 0, e
	}
	if allowed == types.AllActions {
		return allowed, nil
	}

	categories, e := p.og.GroupsOf(obj)
	if e != nil {
		return 0, e
	}
	perms, e := p.Permission.PermissionsFor(sub)
	if e != nil {
		return 0, e
	}

	for category := range categories {
		if perm, ok := perms[category.(types.Category)]; ok {
			allowed |= perm
			if allowed == types.AllActions {
				return allowed, nil
			}
		}
	}

	return allowed, nil
}

func (p *objectGroupedPermission) directPermissionsOn(obj types.Object) (map[types.Subject]types.Action, error) {
	return p.Permission.PermissionsOn(obj)
}

type bothGroupedPermission struct {
	sg types.Grouping
	og types.Grouping
	sp types.Permission
	op types.Permission
	types.Permission
}

// NewBothGroupedPermission make the permission know the relationships between users ans roles,
// as well as articles and categories, and make decisions with them
func NewBothGroupedPermission(sg, og types.Grouping, p types.Permission) *bothGroupedPermission {
	if p == nil {
		p = permission.NewThinPermission()
	}
	return &bothGroupedPermission{
		sg:         sg,
		og:         og,
		sp:         NewSubjectGroupedPermission(sg, p),
		op:         NewObjectGroupedPermission(og, p),
		Permission: p,
	}
}

func (p *bothGroupedPermission) Shall(sub types.Subject, obj types.Object, act types.Action) (bool, error) {
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
			perm, e := p.Permission.PermittedActions(role.(types.Role), cat.(types.Category))
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

func (p *bothGroupedPermission) PermissionsOn(obj types.Object) (map[types.Subject]types.Action, error) {
	return p.op.PermissionsOn(obj)
}

func (p *bothGroupedPermission) PermissionsFor(sub types.Subject) (map[types.Object]types.Action, error) {
	return p.sp.PermissionsFor(sub)
}

func (p *bothGroupedPermission) PermittedActions(sub types.Subject, obj types.Object) (types.Action, error) {
	allowed, e := p.Permission.PermittedActions(sub, obj)
	if e != nil {
		return 0, e
	}
	if allowed == types.AllActions {
		return allowed, nil
	}

	perm, e := p.sp.PermittedActions(sub, obj)
	if e != nil {
		return 0, e
	}

	allowed |= perm
	if allowed == types.AllActions {
		return allowed, nil
	}

	perm, e = p.op.PermittedActions(sub, obj)
	if e != nil {
		return 0, e
	}
	allowed |= perm
	if allowed == types.AllActions {
		return allowed, nil
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
			act, e := p.Permission.PermittedActions(role.(types.Role), cat.(types.Category))
			if e != nil {
				return 0, e
			}

			allowed |= act
			if allowed == types.AllActions {
				return allowed, nil
			}
		}
	}

	return allowed, nil
}

func (p *bothGroupedPermission) directPermissionsFor(sub types.Subject) (map[types.Object]types.Action, error) {
	return p.Permission.PermissionsFor(sub)
}

func (p *bothGroupedPermission) directPermissionsOn(obj types.Object) (map[types.Subject]types.Action, error) {
	return p.Permission.PermissionsOn(obj)
}
