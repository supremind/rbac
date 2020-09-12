package decision

import (
	"github.com/houz42/rbac/types"
)

var _ types.DecisionMaker = (*decisionMaker)(nil)

type decisionMaker struct {
	sg types.Grouping // optional, subject grouping
	og types.Grouping // optional, object grouping
	p  types.Permission

	uap map[types.User]map[types.Article]types.Action // cache user -> article -> action permissions
}

// NewDecisionMaker creates a new decision maker
func NewDecisionMaker(sg types.Grouping, og types.Grouping, p types.Permission) *decisionMaker {
	return &decisionMaker{
		sg:  sg,
		og:  og,
		p:   p,
		uap: make(map[types.User]map[types.Article]types.Action),
	}
}

// SubjectJoin joins a user or a sub role to a role
func (dm *decisionMaker) SubjectJoin(sub types.Subject, role types.Role) error {
	if e := dm.sg.Join(sub, role); e != nil {
		return e
	}

	switch sub.(type) {
	case types.User:
		return dm.completeUserByRole(sub.(types.User), role)

	case types.Role:
		users, e := dm.sg.IndividualsIn(sub.(types.Role))
		if e != nil {
			return e
		}
		for m := range users {
			if e := dm.completeUserByRole(m.(types.User), role); e != nil {
				return e
			}
		}

	default:
		return types.ErrInvlaidSubject
	}

	return nil
}

// SubjectLeave removes a user or a sub role from a role
func (dm *decisionMaker) SubjectLeave(sub types.Subject, role types.Role) error {
	if e := dm.sg.Leave(sub, role); e != nil {
		return e
	}

	switch sub.(type) {
	case types.User:
		return dm.rebuildUser(sub.(types.User))

	case types.Role:
		users, e := dm.sg.IndividualsIn(sub.(types.Role))
		if e != nil {
			return e
		}
		for user := range users {
			if e := dm.rebuildUser(user.(types.User)); e != nil {
				return e
			}
		}

	default:
		return types.ErrInvlaidSubject
	}

	return nil
}

// RemoveUser removes a user and all policies about it
func (dm *decisionMaker) RemoveUser(user types.User) error {
	delete(dm.uap, user)
	return dm.sg.RemoveIndividual(user)
}

// RemoveRole removes a role and all policies about it
func (dm *decisionMaker) RemoveRole(role types.Role) error {
	users, e := dm.sg.IndividualsIn(role)
	if e != nil {
		return e
	}

	if e := dm.sg.RemoveGroup(role); e != nil {
		return e
	}

	for user := range users {
		if e := dm.rebuildUser(user.(types.User)); e != nil {
			return e
		}
	}

	return nil
}

// Subjects returns the GroupingReader interface for subjects
func (dm *decisionMaker) Subjects() types.GroupingReader {
	return dm.sg.(types.GroupingReader)
}

// ObjectJoin joins an article or a sub category to a category
func (dm *decisionMaker) ObjectJoin(obj types.Object, cat types.Category) error {
	if e := dm.og.Join(obj, cat); e != nil {
		return e
	}

	switch obj.(type) {
	case types.Article:
		return dm.completeArticleByCategory(obj.(types.Article), cat)

	case types.Category:
		arts, e := dm.og.IndividualsIn(obj.(types.Category))
		if e != nil {
			for art := range arts {
				if e := dm.completeArticleByCategory(art.(types.Article), cat); e != nil {
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
func (dm *decisionMaker) ObjectLeave(obj types.Object, cat types.Category) error {
	if e := dm.og.Leave(obj, cat); e != nil {
		return e
	}

	switch obj.(type) {
	case types.Article:
		return dm.rebuildArticle(obj.(types.Article))

	case types.Category:
		arts, e := dm.og.IndividualsIn(obj.(types.Category))
		if e != nil {
			return e
		}
		for art := range arts {
			if e := dm.rebuildArticle(art.(types.Article)); e != nil {
				return e
			}
		}

	default:
		return types.ErrInvlaidObject
	}

	return nil
}

// RemoveArticle removes an article and all polices about it
func (dm *decisionMaker) RemoveArticle(art types.Article) error {
	if e := dm.og.RemoveIndividual(art); e != nil {
		return e
	}

	for _, perms := range dm.uap {
		delete(perms, art)
	}

	return nil
}

// RemoveCategory removes a category and all polices about it
func (dm *decisionMaker) RemoveCategory(cat types.Category) error {
	arts, e := dm.og.IndividualsIn(cat)
	if e != nil {
		return e
	}

	if e := dm.og.RemoveGroup(cat); e != nil {
		return e
	}

	for art := range arts {
		if e := dm.rebuildArticle(art.(types.Article)); e != nil {
			return e
		}
	}

	return nil
}

// Objects returns the types.GroupingReader interface for objects
func (dm *decisionMaker) Objects() types.GroupingReader {
	return dm.og.(types.GroupingReader)
}

// Permit subject to perform action on object
func (dm *decisionMaker) Permit(sub types.Subject, obj types.Object, act types.Action) error {
	if e := dm.p.Permit(sub, obj, act); e != nil {
		return e
	}

	users := make(map[types.Member]struct{}, 1)
	arts := make(map[types.Member]struct{})

	switch sub.(type) {
	case types.User:
		users[sub.(types.User)] = struct{}{}

	case types.Role:
		if dm.sg == nil {
			return types.ErrNoSubjectGrouping
		}

		us, e := dm.sg.IndividualsIn(sub.(types.Role))
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
		if dm.og == nil {
			return types.ErrNoObjectGrouping
		}

		as, e := dm.og.IndividualsIn(obj.(types.Category))
		if e != nil {
			return e
		}
		arts = as

	default:
		return types.ErrInvlaidObject
	}

	for u := range users {
		user := u.(types.User)
		if dm.uap[user] == nil {
			dm.uap[user] = make(map[types.Article]types.Action)
		}

		for a := range arts {
			art := a.(types.Article)
			dm.uap[user][art] |= act
		}
	}

	return nil
}

// Revoke permission for subject to perform action on object
func (dm *decisionMaker) Revoke(sub types.Subject, obj types.Object, act types.Action) error {
	if e := dm.p.Revoke(sub, obj, act); e != nil {
		return e
	}

	removeByUser := func(user types.User) error {
		if dm.uap[user] == nil {
			return nil
		}

		switch obj.(type) {
		case types.Article:
			delete(dm.uap[user], obj.(types.Article))

		case types.Category:
			if dm.og == nil {
				return types.ErrNoObjectGrouping
			}

			arts, e := dm.og.IndividualsIn(obj.(types.Category))
			if e != nil {
				return e
			}
			for art := range arts {
				delete(dm.uap[user], art.(types.Article))
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
		if dm.sg == nil {
			return types.ErrNoSubjectGrouping
		}

		users, e := dm.sg.IndividualsIn(sub.(types.Role))
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
func (dm *decisionMaker) Shall(sub types.Subject, obj types.Object, act types.Action) (bool, error) {

	if user, ok := sub.(types.User); ok {
		if art, ok := obj.(types.Article); ok {
			if dm.uap[user] != nil {
				return dm.uap[user][art].Includes(act), nil
			}
			return false, nil
		}
	}

	return dm.p.Shall(sub, obj, act)
}

// PermissionsOn object for all subjects
func (dm *decisionMaker) PermissionsOn(obj types.Object) (map[types.Subject]types.Action, error) {
	return dm.p.PermissionsOn(obj)
}

// PermissionsFor subject on all objects
func (dm *decisionMaker) PermissionsFor(sub types.Subject) (map[types.Object]types.Action, error) {
	return dm.p.PermissionsFor(sub)
}

// PermittedActions for subject on object
func (dm *decisionMaker) PermittedActions(sub types.Subject, obj types.Object) (types.Action, error) {
	return dm.p.PermittedActions(sub, obj)
}

func (dm *decisionMaker) rebuildUser(user types.User) error {
	if dm.sg == nil {
		return types.ErrNoSubjectGrouping
	}

	roles, e := dm.sg.GroupsOf(user)
	if e != nil {
		return e
	}

	for role := range roles {
		if e := dm.completeUserByRole(user, role.(types.Role)); e != nil {
			return e
		}
	}

	return nil
}

func (dm *decisionMaker) completeUserByRole(user types.User, role types.Role) error {
	perms, e := dm.p.PermissionsFor(role)
	if e != nil {
		return e
	}

	if dm.uap[user] == nil {
		dm.uap[user] = make(map[types.Article]types.Action, len(perms))
	}

	for obj, act := range perms {
		if art, ok := obj.(types.Article); ok {
			dm.uap[user][art] |= act
		}
	}

	return nil
}

func (dm *decisionMaker) rebuildArticle(art types.Article) error {
	if dm.og == nil {
		return types.ErrNoObjectGrouping
	}

	cats, e := dm.og.GroupsOf(art)
	if e != nil {
		return e
	}

	for cat := range cats {
		if e := dm.completeArticleByCategory(art, cat.(types.Category)); e != nil {
			return e
		}
	}

	return nil
}

func (dm *decisionMaker) completeArticleByCategory(art types.Article, cat types.Category) error {
	perms, e := dm.p.PermissionsOn(cat)
	if e != nil {
		return e
	}

	for sub, act := range perms {
		if user, ok := sub.(types.User); ok {
			if dm.uap[user] == nil {
				dm.uap = make(map[types.User]map[types.Article]types.Action, 1)
			}
			dm.uap[user][art] |= act
		}
	}

	return nil
}
