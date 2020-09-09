package rbac

import "fmt"

var _ Grouping = (*slimGrouping)(nil)

// slimGrouping is a simplest implementation of Grouping interface
// it is used as a prototype of concept and baseline for testing
type slimGrouping struct {
	parents  map[Subject]map[Role]struct{}
	children map[Role]map[Subject]struct{}
	maxDepth int
}

func newSlimGrouping() *slimGrouping {
	return &slimGrouping{
		parents:  make(map[Subject]map[Role]struct{}),
		children: make(map[Role]map[Subject]struct{}),
		maxDepth: 10,
	}
}

// Join implements Grouping interface
func (g *slimGrouping) Join(sub Subject, role Role) error {
	if g.parents[sub] == nil {
		g.parents[sub] = make(map[Role]struct{}, 1)
	}
	g.parents[sub][role] = struct{}{}

	if g.children[role] == nil {
		g.children[role] = make(map[Subject]struct{})
	}
	g.children[role][sub] = struct{}{}

	return nil
}

// Leave implements Grouping interfaceJ
func (g *slimGrouping) Leave(sub Subject, role Role) error {
	if g.parents[sub] == nil {
		return fmt.Errorf("%w: grouping rule: %s -> %s", ErrNotFound, sub.subject(), role.subject())
	}
	delete(g.parents[sub], role)

	if g.children[role] == nil {
		return fmt.Errorf("%w: grouping rule: %s -> %s", ErrNotFound, role.subject(), sub.subject())
	}
	delete(g.children[role], sub)

	return nil
}

// IsIn implements Grouping interface
func (g *slimGrouping) IsIn(user User, role Role) (bool, error) {
	roles, err := g.RolesOf(user)
	if err != nil {
		return false, err
	}

	_, ok := roles[role]
	return ok, nil
}

// AllRoles implements Grouping interface
func (g *slimGrouping) AllRoles() (map[Role]struct{}, error) {
	roles := make(map[Role]struct{}, len(g.children))
	for role := range g.children {
		roles[role] = struct{}{}
	}
	return roles, nil
}

// AllUsers implements Grouping interface
func (g *slimGrouping) AllUsers() (map[User]struct{}, error) {
	users := make(map[User]struct{}, len(g.parents))
	for sub := range g.parents {
		if user, ok := sub.(User); ok {
			users[user] = struct{}{}
		}
	}
	return users, nil
}

// RolesOf implements Grouping interface
func (g *slimGrouping) RolesOf(user User) (map[Role]struct{}, error) {
	ancients := make(map[Role]struct{})

	var query func(sub Subject, depth int)
	query = func(sub Subject, depth int) {
		if depth > g.maxDepth {
			return
		}
		for r := range g.parents[sub] {
			ancients[r] = struct{}{}
			query(r, depth+1)
		}
	}
	query(user, 0)

	return ancients, nil
}

// UsersOf implements Grouping interface
func (g *slimGrouping) UsersOf(role Role) (map[User]struct{}, error) {
	children := make(map[User]struct{})

	var query func(role Role, depth int)
	query = func(role Role, depth int) {
		if depth > g.maxDepth {
			return
		}
		for ch := range g.children[role] {
			if user, ok := ch.(User); ok {
				children[user] = struct{}{}
			} else {
				query(ch.(Role), depth+1)
			}
		}
	}
	query(role, 0)

	return children, nil
}

func (g *slimGrouping) DirectRolesOf(sub Subject) (map[Role]struct{}, error) {
	return g.parents[sub], nil
}

func (g *slimGrouping) DirectSubjectsOf(role Role) (map[Subject]struct{}, error) {
	return g.children[role], nil
}

// RemoveRole implements Grouping interface
func (g *slimGrouping) RemoveRole(role Role) error {
	children := g.children[role]
	parents := g.parents[role]

	delete(g.children, role)
	delete(g.parents, role)

	for ch := range children {
		delete(g.parents[ch], role)
	}
	for p := range parents {
		delete(g.children[p], role)
	}

	return nil
}

// RemoveUser implements Grouping interface
func (g *slimGrouping) RemoveUser(user User) error {
	parents := g.parents[user]
	delete(g.parents, user)

	for p := range parents {
		delete(g.children[p], user)
	}
	return nil
}
