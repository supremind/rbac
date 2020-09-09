package rbac

var _ Grouping = (*fatGrouping)(nil)

// fatGrouping caches more information to speed up querying
// fatGrouping is faster on quering, and slower on removing comprared to slimGrouping
type fatGrouping struct {
	slim slimGrouping // no sense to use another implementation

	// subject => all roles it belongs to
	roles map[Subject]map[Role]struct{}
	// role => all users belongs to it
	users map[Role]map[User]struct{}

	allUsers map[User]struct{}
	allRoles map[Role]struct{}
}

func newFatGrouping() *fatGrouping {
	return &fatGrouping{
		slim:     *newSlimGrouping(),
		roles:    make(map[Subject]map[Role]struct{}),
		users:    make(map[Role]map[User]struct{}),
		allUsers: make(map[User]struct{}),
		allRoles: make(map[Role]struct{}),
	}
}

func (g *fatGrouping) Join(sub Subject, role Role) error {
	if e := g.slim.Join(sub, role); e != nil {
		return e
	}

	g.allRoles[role] = struct{}{}
	if user, ok := sub.(User); ok {
		g.allUsers[user] = struct{}{}
	}

	if g.roles[sub] == nil {
		g.roles[sub] = make(map[Role]struct{})
	}
	g.roles[sub][role] = struct{}{}
	for rr := range g.roles[role] {
		g.roles[sub][rr] = struct{}{}
	}

	if g.users[role] == nil {
		g.users[role] = make(map[User]struct{})
	}
	if user, ok := sub.(User); ok {
		g.users[role][user] = struct{}{}
	} else {
		for u := range g.users[sub.(Role)] {
			g.users[role][u] = struct{}{}
		}
	}

	return nil
}

func (g *fatGrouping) Leave(sub Subject, role Role) error {
	if e := g.slim.Leave(sub, role); e != nil {
		return e
	}

	if e := g.rebuildRoles(sub); e != nil {
		return e
	}
	if e := g.rebuildUsers(role); e != nil {
		return e
	}
	return nil
}

func (g *fatGrouping) IsIn(user User, role Role) (bool, error) {
	if users, ok := g.users[role]; ok {
		_, ok := users[user]
		return ok, nil
	}
	return false, nil
}

func (g *fatGrouping) AllRoles() (map[Role]struct{}, error) {
	return g.allRoles, nil
}

func (g *fatGrouping) AllUsers() (map[User]struct{}, error) {
	return g.allUsers, nil
}

func (g *fatGrouping) RolesOf(user User) (map[Role]struct{}, error) {
	return g.roles[user], nil
}

func (g *fatGrouping) UsersOf(role Role) (map[User]struct{}, error) {
	return g.users[role], nil
}

func (g *fatGrouping) DirectRolesOf(sub Subject) (map[Role]struct{}, error) {
	return g.slim.DirectRolesOf(sub)
}

func (g *fatGrouping) DirectSubjectsOf(role Role) (map[Subject]struct{}, error) {
	return g.slim.DirectSubjectsOf(role)
}

func (g *fatGrouping) RemoveRole(role Role) error {
	delete(g.allRoles, role)
	delete(g.users, role)
	delete(g.roles, role)

	subs, e := g.DirectSubjectsOf(role)
	if e != nil {
		return e
	}
	roles, e := g.DirectRolesOf(role)
	if e != nil {
		return e
	}

	if e := g.slim.RemoveRole(role); e != nil {
		return e
	}

	for sub := range subs {
		if e := g.rebuildRoles(sub); e != nil {
			return e
		}
	}
	for role := range roles {
		if e := g.rebuildUsers(role); e != nil {
			return e
		}
	}

	return nil
}

func (g *fatGrouping) RemoveUser(user User) error {
	delete(g.allUsers, user)
	delete(g.roles, user)

	roles, e := g.DirectRolesOf(user)
	if e != nil {
		return e
	}

	if e := g.slim.RemoveUser(user); e != nil {
		return e
	}

	for role := range roles {
		if e := g.rebuildUsers(role); e != nil {
			return e
		}
	}

	return nil
}

func (g *fatGrouping) rebuildRoles(sub Subject) error {
	// rebuild roles for subject
	roles, e := g.DirectRolesOf(sub)
	if e != nil {
		return e
	}
	g.roles[sub] = make(map[Role]struct{}, len(roles))
	for role := range roles {
		g.roles[sub][role] = struct{}{}
		for rr := range g.roles[role] {
			g.roles[sub][rr] = struct{}{}
		}
	}

	if role, ok := sub.(Role); ok {
		// rebuild roles for all subjects of sub
		// fixme: some subject may be rebuilt more than once
		subs, e := g.DirectSubjectsOf(role)
		if e != nil {
			return e
		}
		for sub := range subs {
			if e := g.rebuildRoles(sub); e != nil {
				return e
			}
		}
	}

	return nil
}

func (g *fatGrouping) rebuildUsers(role Role) error {
	// rebuild users of role
	subs, e := g.DirectSubjectsOf(role)
	if e != nil {
		return e
	}

	g.users[role] = make(map[User]struct{}, len(subs))
	for sub := range subs {
		if user, ok := sub.(User); ok {
			g.users[role][user] = struct{}{}
		} else {
			for user := range g.users[sub.(Role)] {
				g.users[role][user] = struct{}{}
			}
		}
	}

	// rebuild users for all roles of role
	// fixme: some role may be rebuilt more than once
	roles, e := g.DirectRolesOf(role)
	if e != nil {
		return e
	}
	for role := range roles {
		if e := g.rebuildUsers(role); e != nil {
			return e
		}
	}

	return nil
}
