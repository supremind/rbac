package rbac

var _ DecisionMaker = (*decisionMaker)(nil)

type decisionMaker struct {
	sg Grouping // optional, subject grouping
	og Grouping // optional, object grouping
	p  Permission

	uap map[User]map[Article]Action // cache user -> article -> action permissions
}

func newDecisionMaker(sg Grouping, og Grouping, p Permission) *decisionMaker {
	return &decisionMaker{
		sg:  sg,
		og:  og,
		p:   p,
		uap: make(map[User]map[Article]Action),
	}
}

// SubjectJoin joins a user or a sub role to a role
func (dm *decisionMaker) SubjectJoin(sub Subject, role Role) error {
	if e := dm.sg.Join(sub, role); e != nil {
		return e
	}

	switch sub.(type) {
	case User:
		return dm.completeUserByRole(sub.(User), role)

	case Role:
		users, e := dm.sg.IndividualsIn(sub.(Role))
		if e != nil {
			return e
		}
		for ind := range users {
			if e := dm.completeUserByRole(ind.(User), role); e != nil {
				return e
			}
		}

	default:
		return ErrInvlaidSubject
	}

	return nil
}

// SubjectLeave removes a user or a sub role from a role
func (dm *decisionMaker) SubjectLeave(sub Subject, role Role) error {
	if e := dm.sg.Leave(sub, role); e != nil {
		return e
	}

	switch sub.(type) {
	case User:
		return dm.rebuildUser(sub.(User))

	case Role:
		users, e := dm.sg.IndividualsIn(sub.(Role))
		if e != nil {
			return e
		}
		for user := range users {
			if e := dm.rebuildUser(user.(User)); e != nil {
				return e
			}
		}

	default:
		return ErrInvlaidSubject
	}

	return nil
}

// RemoveUser removes a user and all policies about it
func (dm *decisionMaker) RemoveUser(user User) error {
	delete(dm.uap, user)
	return dm.sg.RemoveIndividual(user)
}

// RemoveRole removes a role and all policies about it
func (dm *decisionMaker) RemoveRole(role Role) error {
	users, e := dm.sg.IndividualsIn(role)
	if e != nil {
		return e
	}

	if e := dm.sg.RemoveGroup(role); e != nil {
		return e
	}

	for user := range users {
		if e := dm.rebuildUser(user.(User)); e != nil {
			return e
		}
	}

	return nil
}

// Subjects returns the GroupingReader interface for subjects
func (dm *decisionMaker) Subjects() GroupingReader {
	return dm.sg.(GroupingReader)
}

// ObjectJoin joins an article or a sub category to a category
func (dm *decisionMaker) ObjectJoin(obj Object, cat Category) error {
	if e := dm.og.Join(obj, cat); e != nil {
		return e
	}

	switch obj.(type) {
	case Article:
		return dm.completeArticleByCategory(obj.(Article), cat)

	case Category:
		arts, e := dm.og.IndividualsIn(obj.(Category))
		if e != nil {
			for art := range arts {
				if e := dm.completeArticleByCategory(art.(Article), cat); e != nil {
					return e
				}
			}
		}

	default:
		return ErrInvlaidObject
	}

	return nil
}

// ObjectLeave removes an article or a sub category from a category
func (dm *decisionMaker) ObjectLeave(obj Object, cat Category) error {
	if e := dm.og.Leave(obj, cat); e != nil {
		return e
	}

	switch obj.(type) {
	case Article:
		return dm.rebuildArticle(obj.(Article))

	case Category:
		arts, e := dm.og.IndividualsIn(obj.(Category))
		if e != nil {
			return e
		}
		for art := range arts {
			if e := dm.rebuildArticle(art.(Article)); e != nil {
				return e
			}
		}

	default:
		return ErrInvlaidObject
	}

	return nil
}

// RemoveArticle removes an article and all polices about it
func (dm *decisionMaker) RemoveArticle(art Article) error {
	if e := dm.og.RemoveIndividual(art); e != nil {
		return e
	}

	for _, perms := range dm.uap {
		delete(perms, art)
	}

	return nil
}

// RemoveCategory removes a category and all polices about it
func (dm *decisionMaker) RemoveCategory(cat Category) error {
	arts, e := dm.og.IndividualsIn(cat)
	if e != nil {
		return e
	}

	if e := dm.og.RemoveGroup(cat); e != nil {
		return e
	}

	for art := range arts {
		if e := dm.rebuildArticle(art.(Article)); e != nil {
			return e
		}
	}

	return nil
}

// Objects returns the GroupingReader interface for objects
func (dm *decisionMaker) Objects() GroupingReader {
	return dm.og.(GroupingReader)
}

// Permit subject to perform action on object
func (dm *decisionMaker) Permit(sub Subject, obj Object, act Action) error {
	if e := dm.p.Permit(sub, obj, act); e != nil {
		return e
	}

	users := make(map[Individual]struct{}, 1)
	arts := make(map[Individual]struct{})

	switch sub.(type) {
	case User:
		users[sub.(User)] = struct{}{}

	case Role:
		if dm.sg == nil {
			return ErrNoSubjectGrouping
		}

		us, e := dm.sg.IndividualsIn(sub.(Role))
		if e != nil {
			return e
		}
		users = us

	default:
		return ErrInvlaidSubject
	}

	switch obj.(type) {
	case Article:
		arts[obj.(Article)] = struct{}{}

	case Category:
		if dm.og == nil {
			return ErrNoObjectGrouping
		}

		as, e := dm.og.IndividualsIn(obj.(Category))
		if e != nil {
			return e
		}
		arts = as

	default:
		return ErrInvlaidObject
	}

	for u := range users {
		user := u.(User)
		if dm.uap[user] == nil {
			dm.uap[user] = make(map[Article]Action)
		}

		for a := range arts {
			art := a.(Article)
			dm.uap[user][art] |= act
		}
	}

	return nil
}

// Revoke permission for subject to perform action on object
func (dm *decisionMaker) Revoke(sub Subject, obj Object, act Action) error {
	if e := dm.p.Revoke(sub, obj, act); e != nil {
		return e
	}

	removeByUser := func(user User) error {
		if dm.uap[user] == nil {
			return nil
		}

		switch obj.(type) {
		case Article:
			delete(dm.uap[user], obj.(Article))

		case Category:
			if dm.og == nil {
				return ErrNoObjectGrouping
			}

			arts, e := dm.og.IndividualsIn(obj.(Category))
			if e != nil {
				return e
			}
			for art := range arts {
				delete(dm.uap[user], art.(Article))
			}

		default:
			return ErrInvlaidObject
		}

		return nil
	}

	switch sub.(type) {
	case User:
		return removeByUser(sub.(User))

	case Role:
		if dm.sg == nil {
			return ErrNoSubjectGrouping
		}

		users, e := dm.sg.IndividualsIn(sub.(Role))
		if e != nil {
			return e
		}

		for user := range users {
			if e := removeByUser(user.(User)); e != nil {
				return e
			}
		}

	default:
		return ErrInvlaidObject
	}

	return nil
}

// Shall subject to perform action on object
func (dm *decisionMaker) Shall(sub Subject, obj Object, act Action) (bool, error) {

	if user, ok := sub.(User); ok {
		if art, ok := obj.(Article); ok {
			if dm.uap[user] != nil {
				return dm.uap[user][art].Includes(act), nil
			}
			return false, nil
		}
	}

	return dm.p.Shall(sub, obj, act)
}

// PermissionsOn object for all subjects
func (dm *decisionMaker) PermissionsOn(obj Object) (map[Subject]Action, error) {
	return dm.p.PermissionsOn(obj)
}

// PermissionsFor subject on all objects
func (dm *decisionMaker) PermissionsFor(sub Subject) (map[Object]Action, error) {
	return dm.p.PermissionsFor(sub)
}

// PermittedActions for subject on object
func (dm *decisionMaker) PermittedActions(sub Subject, obj Object) (Action, error) {
	return dm.p.PermittedActions(sub, obj)
}

func (dm *decisionMaker) rebuildUser(user User) error {
	if dm.sg == nil {
		return ErrNoSubjectGrouping
	}

	roles, e := dm.sg.GroupsOf(user)
	if e != nil {
		return e
	}

	for role := range roles {
		if e := dm.completeUserByRole(user, role.(Role)); e != nil {
			return e
		}
	}

	return nil
}

func (dm *decisionMaker) completeUserByRole(user User, role Role) error {
	perms, e := dm.p.PermissionsFor(role)
	if e != nil {
		return e
	}

	if dm.uap[user] == nil {
		dm.uap[user] = make(map[Article]Action, len(perms))
	}

	for obj, act := range perms {
		if art, ok := obj.(Article); ok {
			dm.uap[user][art] |= act
		}
	}

	return nil
}

func (dm *decisionMaker) rebuildArticle(art Article) error {
	if dm.og == nil {
		return ErrNoObjectGrouping
	}

	cats, e := dm.og.GroupsOf(art)
	if e != nil {
		return e
	}

	for cat := range cats {
		if e := dm.completeArticleByCategory(art, cat.(Category)); e != nil {
			return e
		}
	}

	return nil
}

func (dm *decisionMaker) completeArticleByCategory(art Article, cat Category) error {
	perms, e := dm.p.PermissionsOn(cat)
	if e != nil {
		return e
	}

	for sub, act := range perms {
		if user, ok := sub.(User); ok {
			if dm.uap[user] == nil {
				dm.uap = make(map[User]map[Article]Action, 1)
			}
			dm.uap[user][art] |= act
		}
	}

	return nil
}
