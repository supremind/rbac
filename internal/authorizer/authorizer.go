package authorizer

import (
	"github.com/houz42/rbac/types"
)

var _ types.Authorizer = (*authorizer)(nil)

type authorizer struct {
	sg types.Grouping // optional, subject grouping
	og types.Grouping // optional, object grouping
	p  types.Permission

	uap map[types.User]map[types.Article]types.Action // cache user -> article -> action permissions
}

// NewAuthorizer creates a simple authorizer, which should not be used directly
func NewAuthorizer(sg types.Grouping, og types.Grouping, p types.Permission) *authorizer {
	return &authorizer{
		sg:  sg,
		og:  og,
		p:   p,
		uap: make(map[types.User]map[types.Article]types.Action),
	}
}

// SubjectJoin joins a user or a sub role to a role
func (authz *authorizer) SubjectJoin(sub types.Subject, role types.Role) error {
	if e := authz.sg.Join(sub, role); e != nil {
		return e
	}

	switch sub.(type) {
	case types.User:
		return authz.completeUserByRole(sub.(types.User), role)

	case types.Role:
		users, e := authz.sg.MembersIn(sub.(types.Role))
		if e != nil {
			return e
		}
		for m := range users {
			if e := authz.completeUserByRole(m.(types.User), role); e != nil {
				return e
			}
		}

	default:
		return types.ErrInvlaidSubject
	}

	return nil
}

// SubjectLeave removes a user or a sub role from a role
func (authz *authorizer) SubjectLeave(sub types.Subject, role types.Role) error {
	if e := authz.sg.Leave(sub, role); e != nil {
		return e
	}

	switch sub.(type) {
	case types.User:
		return authz.rebuildUser(sub.(types.User))

	case types.Role:
		users, e := authz.sg.MembersIn(sub.(types.Role))
		if e != nil {
			return e
		}
		for user := range users {
			if e := authz.rebuildUser(user.(types.User)); e != nil {
				return e
			}
		}

	default:
		return types.ErrInvlaidSubject
	}

	return nil
}

// RemoveUser removes a user and all policies about it
func (authz *authorizer) RemoveUser(user types.User) error {
	sgp, ok := authz.p.(subjectGroupedPermissioner)
	if !ok {
		return types.ErrNoSubjectGrouping
	}

	delete(authz.uap, user)

	perms, e := sgp.directPermissionsFor(user)
	if e != nil {
		return e
	}
	for obj, act := range perms {
		if e := sgp.Revoke(user, obj, act); e != nil {
			return e
		}
	}

	return authz.sg.RemoveMember(user)
}

// RemoveRole removes a role and all policies about it
func (authz *authorizer) RemoveRole(role types.Role) error {
	sgp, ok := authz.p.(subjectGroupedPermissioner)
	if !ok {
		return types.ErrNoSubjectGrouping
	}

	users, e := authz.sg.MembersIn(role)
	if e != nil {
		return e
	}

	if e := authz.sg.RemoveGroup(role); e != nil {
		return e
	}

	for user := range users {
		if e := authz.rebuildUser(user.(types.User)); e != nil {
			return e
		}
	}

	perms, e := sgp.directPermissionsFor(role)
	if e != nil {
		return e
	}
	for obj, act := range perms {
		if e := sgp.Revoke(role, obj, act); e != nil {
			return e
		}
	}

	return nil
}

// Subjects returns the GroupingReader interface for subjects
func (authz *authorizer) Subjects() types.GroupingReader {
	return authz.sg.(types.GroupingReader)
}

// ObjectJoin joins an article or a sub category to a category
func (authz *authorizer) ObjectJoin(obj types.Object, cat types.Category) error {
	if e := authz.og.Join(obj, cat); e != nil {
		return e
	}

	switch obj.(type) {
	case types.Article:
		return authz.completeArticleByCategory(obj.(types.Article), cat)

	case types.Category:
		arts, e := authz.og.MembersIn(obj.(types.Category))
		if e != nil {
			for art := range arts {
				if e := authz.completeArticleByCategory(art.(types.Article), cat); e != nil {
					return e
				}
			}
		}

	default:
		return types.ErrInvlaidObject
	}

	return nil
}

// ObjectLeave removes an article or a sub category from a category
func (authz *authorizer) ObjectLeave(obj types.Object, cat types.Category) error {
	if e := authz.og.Leave(obj, cat); e != nil {
		return e
	}

	switch obj.(type) {
	case types.Article:
		return authz.rebuildArticle(obj.(types.Article))

	case types.Category:
		arts, e := authz.og.MembersIn(obj.(types.Category))
		if e != nil {
			return e
		}
		for art := range arts {
			if e := authz.rebuildArticle(art.(types.Article)); e != nil {
				return e
			}
		}

	default:
		return types.ErrInvlaidObject
	}

	return nil
}

// RemoveArticle removes an article and all polices about it
func (authz *authorizer) RemoveArticle(art types.Article) error {
	ogp, ok := authz.p.(objectGroupedPermissioner)
	if !ok {
		return types.ErrNoObjectGrouping
	}

	if e := authz.og.RemoveMember(art); e != nil {
		return e
	}

	for _, perms := range authz.uap {
		delete(perms, art)
	}

	perms, e := ogp.directPermissionsOn(art)
	if e != nil {
		return e
	}
	for sub, act := range perms {
		if e := ogp.Revoke(sub, art, act); e != nil {
			return e
		}
	}

	return nil
}

// RemoveCategory removes a category and all polices about it
func (authz *authorizer) RemoveCategory(cat types.Category) error {
	ogp, ok := authz.p.(objectGroupedPermissioner)
	if !ok {
		return types.ErrNoObjectGrouping
	}

	arts, e := authz.og.MembersIn(cat)
	if e != nil {
		return e
	}

	if e := authz.og.RemoveGroup(cat); e != nil {
		return e
	}

	for art := range arts {
		if e := authz.rebuildArticle(art.(types.Article)); e != nil {
			return e
		}
	}

	perms, e := ogp.directPermissionsOn(cat)
	if e != nil {
		return e
	}
	for sub, act := range perms {
		if e := ogp.Revoke(sub, cat, act); e != nil {
			return e
		}
	}

	return nil
}

// Objects returns the types.GroupingReader interface for objects
func (authz *authorizer) Objects() types.GroupingReader {
	return authz.og.(types.GroupingReader)
}

// Permit subject to perform action on object
func (authz *authorizer) Permit(sub types.Subject, obj types.Object, act types.Action) error {
	if e := authz.p.Permit(sub, obj, act); e != nil {
		return e
	}

	users := make(map[types.Member]struct{}, 1)
	arts := make(map[types.Member]struct{})

	switch sub.(type) {
	case types.User:
		users[sub.(types.User)] = struct{}{}

	case types.Role:
		if authz.sg == nil {
			return types.ErrNoSubjectGrouping
		}

		us, e := authz.sg.MembersIn(sub.(types.Role))
		if e != nil {
			return e
		}
		users = us

	default:
		return types.ErrInvlaidSubject
	}

	switch obj.(type) {
	case types.Article:
		arts[obj.(types.Article)] = struct{}{}

	case types.Category:
		if authz.og == nil {
			return types.ErrNoObjectGrouping
		}

		as, e := authz.og.MembersIn(obj.(types.Category))
		if e != nil {
			return e
		}
		arts = as

	default:
		return types.ErrInvlaidObject
	}

	for u := range users {
		user := u.(types.User)
		if authz.uap[user] == nil {
			authz.uap[user] = make(map[types.Article]types.Action)
		}

		for a := range arts {
			art := a.(types.Article)
			authz.uap[user][art] |= act
		}
	}

	return nil
}

// Revoke permission for subject to perform action on object
func (authz *authorizer) Revoke(sub types.Subject, obj types.Object, act types.Action) error {
	if e := authz.p.Revoke(sub, obj, act); e != nil {
		return e
	}

	removeByUser := func(user types.User) error {
		if authz.uap[user] == nil {
			return nil
		}

		switch obj.(type) {
		case types.Article:
			delete(authz.uap[user], obj.(types.Article))

		case types.Category:
			if authz.og == nil {
				return types.ErrNoObjectGrouping
			}

			arts, e := authz.og.MembersIn(obj.(types.Category))
			if e != nil {
				return e
			}
			for art := range arts {
				delete(authz.uap[user], art.(types.Article))
			}

		default:
			return types.ErrInvlaidObject
		}

		return nil
	}

	switch sub.(type) {
	case types.User:
		return removeByUser(sub.(types.User))

	case types.Role:
		if authz.sg == nil {
			return types.ErrNoSubjectGrouping
		}

		users, e := authz.sg.MembersIn(sub.(types.Role))
		if e != nil {
			return e
		}

		for user := range users {
			if e := removeByUser(user.(types.User)); e != nil {
				return e
			}
		}

	default:
		return types.ErrInvlaidObject
	}

	return nil
}

// Shall subject to perform action on object
func (authz *authorizer) Shall(sub types.Subject, obj types.Object, act types.Action) (bool, error) {

	if user, ok := sub.(types.User); ok {
		if art, ok := obj.(types.Article); ok {
			if authz.uap[user] != nil {
				return authz.uap[user][art].Includes(act), nil
			}
			return false, nil
		}
	}

	return authz.p.Shall(sub, obj, act)
}

// PermissionsOn object for all subjects
func (authz *authorizer) PermissionsOn(obj types.Object) (map[types.Subject]types.Action, error) {
	return authz.p.PermissionsOn(obj)
}

// PermissionsFor subject on all objects
func (authz *authorizer) PermissionsFor(sub types.Subject) (map[types.Object]types.Action, error) {
	return authz.p.PermissionsFor(sub)
}

// PermittedActions for subject on object
func (authz *authorizer) PermittedActions(sub types.Subject, obj types.Object) (types.Action, error) {
	return authz.p.PermittedActions(sub, obj)
}

func (authz *authorizer) rebuildUser(user types.User) error {
	if authz.sg == nil {
		return types.ErrNoSubjectGrouping
	}

	roles, e := authz.sg.GroupsOf(user)
	if e != nil {
		return e
	}

	for role := range roles {
		if e := authz.completeUserByRole(user, role.(types.Role)); e != nil {
			return e
		}
	}

	return nil
}

func (authz *authorizer) completeUserByRole(user types.User, role types.Role) error {
	perms, e := authz.p.PermissionsFor(role)
	if e != nil {
		return e
	}

	if authz.uap[user] == nil {
		authz.uap[user] = make(map[types.Article]types.Action, len(perms))
	}

	for obj, act := range perms {
		if art, ok := obj.(types.Article); ok {
			authz.uap[user][art] |= act
		}
	}

	return nil
}

func (authz *authorizer) rebuildArticle(art types.Article) error {
	if authz.og == nil {
		return types.ErrNoObjectGrouping
	}

	cats, e := authz.og.GroupsOf(art)
	if e != nil {
		return e
	}

	for cat := range cats {
		if e := authz.completeArticleByCategory(art, cat.(types.Category)); e != nil {
			return e
		}
	}

	return nil
}

func (authz *authorizer) completeArticleByCategory(art types.Article, cat types.Category) error {
	perms, e := authz.p.PermissionsOn(cat)
	if e != nil {
		return e
	}

	for sub, act := range perms {
		if user, ok := sub.(types.User); ok {
			if authz.uap[user] == nil {
				authz.uap = make(map[types.User]map[types.Article]types.Action, 1)
			}
			authz.uap[user][art] |= act
		}
	}

	return nil
}
