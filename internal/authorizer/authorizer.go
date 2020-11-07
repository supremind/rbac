package authorizer

import (
	"github.com/go-logr/logr"
	"github.com/supremind/rbac/types"
)

type authorizer struct {
	sg types.Grouping
	og types.Grouping
	p  types.Permission
	l  logr.Logger
}

// New creates an authorizer
func New(sg, og types.Grouping, p types.Permission, l logr.Logger, presets ...types.PresetPolicy) types.Authorizer {
	var a types.Authorizer
	a = &authorizer{
		sg: sg,
		og: og,
		p:  p,
		l:  l,
	}

	a = newSyncedAuthorizer(a)
	a = newWithPresetPolices(a, presets...)

	return a
}

// SubjectJoin joins a user or a sub role to a role
func (a *authorizer) SubjectJoin(sub types.Subject, role types.Role) error {
	a.l.V(4).Info("subject join", "subject", sub, "role", role)

	if a.sg == nil {
		return types.ErrNoSubjectGrouping
	}

	return a.sg.Join(sub, role)
}

// SubjectLeave removes a user or a sub role from a role
func (a *authorizer) SubjectLeave(sub types.Subject, role types.Role) error {
	a.l.V(4).Info("subject leave", "subject", sub, "role", role)

	if a.sg == nil {
		return types.ErrNoSubjectGrouping
	}

	return a.sg.Leave(sub, role)
}

// RemoveUser removes a user and all policies about it
func (a *authorizer) RemoveUser(user types.User) error {
	a.l.V(4).Info("remove user", "user", user)

	if a.sg == nil {
		return types.ErrNoSubjectGrouping
	}

	if e := a.sg.RemoveMember(user); e != nil {
		return e
	}

	perms, e := a.p.PermissionsFor(user)
	if e != nil {
		return e
	}
	for obj, act := range perms {
		if e := a.p.Revoke(user, obj, act); e != nil {
			return e
		}
	}

	return nil
}

// RemoveRole removes a role and all policies about it
func (a *authorizer) RemoveRole(role types.Role) error {
	a.l.V(4).Info("remove role", "role", role)

	if a.sg == nil {
		return types.ErrNoSubjectGrouping
	}

	if e := a.sg.RemoveGroup(role); e != nil {
		return e
	}

	perms, e := a.p.PermissionsFor(role)
	if e != nil {
		return e
	}
	for obj, act := range perms {
		if e := a.p.Revoke(role, obj, act); e != nil {
			return e
		}
	}

	return nil
}

// Subjects returns the GroupingReader interface for subjects
func (a *authorizer) Subjects() types.GroupingReader {
	return a.sg
}

// ObjectJoin joins an article or a sub category to a category
func (a *authorizer) ObjectJoin(obj types.Object, cat types.Category) error {
	a.l.V(4).Info("object join", "object", obj, "category", cat)

	if a.og == nil {
		return types.ErrNoObjectGrouping
	}

	return a.og.Join(obj, cat)
}

// ObjectLeave removes an article or a sub category from a category
func (a *authorizer) ObjectLeave(obj types.Object, cat types.Category) error {
	a.l.V(4).Info("object leave", "object", obj, "category", "cat")

	if a.og == nil {
		return types.ErrNoObjectGrouping
	}

	return a.og.Leave(obj, cat)
}

// RemoveArticle removes an article and all polices about it
func (a *authorizer) RemoveArticle(art types.Article) error {
	a.l.V(4).Info("remove article", "article", art)

	if a.og == nil {
		return types.ErrNoObjectGrouping
	}

	perms, e := a.p.PermissionsOn(art)
	if e != nil {
		return e
	}
	for sub, act := range perms {
		if e := a.p.Revoke(sub, art, act); e != nil {
			return e
		}
	}

	return nil
}

// RemoveCategory removes a category and all polices about it
func (a *authorizer) RemoveCategory(cat types.Category) error {
	a.l.V(4).Info("remove category", "category", cat)

	if a.og == nil {
		return types.ErrNoObjectGrouping
	}

	perms, e := a.p.PermissionsOn(cat)
	if e != nil {
		return e
	}
	for sub, act := range perms {
		if e := a.p.Revoke(sub, cat, act); e != nil {
			return e
		}
	}

	return nil
}

// Objects returns the GroupingReader interface for objects
func (a *authorizer) Objects() types.GroupingReader {
	return a.og
}

// Permit subject to perform action on object
func (a *authorizer) Permit(sub types.Subject, obj types.Object, act types.Action) error {
	a.l.V(4).Info("permit", "subject", sub, "object", obj, "action", act)

	return a.p.Permit(sub, obj, act)
}

// Revoke permission for subject to perform action on object
func (a *authorizer) Revoke(sub types.Subject, obj types.Object, act types.Action) error {
	a.l.V(4).Info("revoke", "subject", sub, "object", obj, "action", act)

	return a.p.Revoke(sub, obj, act)
}

// Shall subject perform action on object
func (a *authorizer) Shall(sub types.Subject, obj types.Object, act types.Action) (bool, error) {
	a.l.V(6).Info("shall", "subject", sub, "object", obj, "action", act)

	allowed, e := a.p.PermittedActions(sub, obj)
	if e != nil {
		return false, e
	}
	if allowed.Includes(act) {
		return true, nil
	}

	act = act.Difference(allowed)

	var roles map[types.Group]struct{}
	if a.sg != nil {
		roles, e = a.sg.GroupsOf(sub)
		if e != nil {
			return false, e
		}

		for role := range roles {
			allowed, e := a.p.PermittedActions(role.(types.Role), obj)
			if e != nil {
				return false, e
			}
			if allowed.Includes(act) {
				return true, nil
			}
			act = act.Difference(allowed)
		}
	}

	var cats map[types.Group]struct{}
	if a.og != nil {
		cats, e = a.og.GroupsOf(obj)
		if e != nil {
			return false, e
		}

		for cat := range cats {
			allowed, e := a.p.PermittedActions(sub, cat.(types.Category))
			if e != nil {
				return false, e
			}
			if allowed.Includes(act) {
				return true, nil
			}
			act = act.Difference(allowed)
		}
	}

	if len(roles) == 0 || len(cats) == 0 {
		return false, nil
	}

	for role := range roles {
		for cat := range cats {
			allowed, e := a.p.PermittedActions(role.(types.Role), cat.(types.Category))
			if e != nil {
				return false, e
			}
			if allowed.Includes(act) {
				return true, nil
			}
			act = act.Difference(allowed)
		}
	}

	return false, nil
}

// PermissionsOn object for all subjects
func (a *authorizer) PermissionsOn(obj types.Object) (map[types.Subject]types.Action, error) {
	perms, e := a.p.PermissionsOn(obj)
	if e != nil {
		return nil, e
	}

	if a.og != nil {
		cats, e := a.og.GroupsOf(obj)
		if e != nil {
			return nil, e
		}

		if perms == nil {
			perms = make(map[types.Subject]types.Action)
		}

		for cat := range cats {
			cp, e := a.p.PermissionsOn(cat.(types.Category))
			if e != nil {
				return nil, e
			}
			for sub, act := range cp {
				perms[sub] |= act
			}
		}
	}

	return perms, nil
}

// PermissionsFor subject on all objects
func (a *authorizer) PermissionsFor(sub types.Subject) (map[types.Object]types.Action, error) {
	perms, e := a.p.PermissionsFor(sub)
	if e != nil {
		return nil, e
	}

	if a.sg != nil {
		roles, e := a.sg.GroupsOf(sub)
		if e != nil {
			return nil, e
		}

		if perms == nil {
			perms = make(map[types.Object]types.Action)
		}

		for role := range roles {
			sp, e := a.p.PermissionsFor(role.(types.Role))
			if e != nil {
				return nil, e
			}
			for obj, act := range sp {
				perms[obj] |= act
			}
		}
	}

	return perms, nil
}

// PermittedActions for subject on object
func (a *authorizer) PermittedActions(sub types.Subject, obj types.Object) (types.Action, error) {
	var act types.Action

	allowed, e := a.p.PermittedActions(sub, obj)
	if e != nil {
		return 0, e
	}
	if act.Includes(types.AllActions) {
		return act, nil
	}
	act |= allowed

	var roles map[types.Group]struct{}
	if a.sg != nil {
		roles, e = a.sg.GroupsOf(sub)
		if e != nil {
			return 0, e
		}

		for role := range roles {
			allowed, e := a.p.PermittedActions(role.(types.Role), obj)
			if e != nil {
				return 0, e
			}
			if act.Includes(types.AllActions) {
				return act, nil
			}
			act |= allowed
		}
	}

	var cats map[types.Group]struct{}
	if a.og != nil {
		cats, e = a.og.GroupsOf(obj)
		if e != nil {
			return 0, e
		}

		for cat := range cats {
			allowed, e := a.p.PermittedActions(sub, cat.(types.Category))
			if e != nil {
				return 0, e
			}
			if act.Includes(types.AllActions) {
				return act, nil
			}
			act |= allowed
		}
	}

	if len(roles) == 0 || len(cats) == 0 {
		return act, nil
	}

	for role := range roles {
		for cat := range cats {
			allowed, e := a.p.PermittedActions(role.(types.Role), cat.(types.Category))
			if e != nil {
				return 0, e
			}
			if act.Includes(types.AllActions) {
				return act, nil
			}
			act |= allowed
		}
	}

	return act, nil
}
