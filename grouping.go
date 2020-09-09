package rbac

import (
	"fmt"
	"strings"
	"sync"
)

type Grouping interface {
	Join(Subject, Role) error
	Leave(Subject, Role) error

	IsIn(User, Role) (bool, error)

	AllRoles() (map[Role]struct{}, error)
	AllUsers() (map[User]struct{}, error)

	RolesOf(User) (map[Role]struct{}, error)
	UsersOf(Role) (map[User]struct{}, error)

	DirectRolesOf(Subject) (map[Role]struct{}, error)
	DirectSubjectsOf(Role) (map[Subject]struct{}, error)

	RemoveRole(Role) error
	RemoveUser(User) error
}

var _ Grouping = (*slimGrouping)(nil)
var _ Grouping = (*fatGrouping)(nil)
var _ Grouping = (*syncedGrouping)(nil)

type Subject interface {
	subject() string
}

type User string

func (u User) subject() string {
	return "user:" + string(u)
}

type Role string

func (r Role) subject() string {
	return "role:" + string(r)
}

func ParseSubject(sub string) (Subject, error) {
	if strings.HasPrefix(sub, "user:") {
		u := strings.TrimPrefix(sub, "user:")
		return User(u), nil
	}
	if strings.HasPrefix(sub, "role:") {
		r := strings.TrimPrefix(sub, "role:")
		return Role(r), nil
	}

	return nil, ErrInvlaidSubject
}

// slimGrouping stores lest information and does everything in memory
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

// fatGrouping stores more information to speed up querying
// fatGrouping is faster on quering, and slower on removing comprared to the innter Grouping
type fatGrouping struct {
	slim slimGrouping // no sense to use other implementations

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
	for r := range g.roles[role] {
		g.roles[sub][r] = struct{}{}
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

	delete(g.allRoles, role)
	if user, ok := sub.(User); ok {
		delete(g.allUsers, user)
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
	// if roles, ok := g.roles[user]; ok {
	// 	_, ok := roles[role]
	// 	return ok, nil
	// }
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

type syncedGrouping struct {
	g Grouping
	sync.RWMutex
}

func newSyncedGrouping(g Grouping) *syncedGrouping {
	return &syncedGrouping{
		g: g,
	}
}

func (g *syncedGrouping) Join(sub Subject, role Role) error {
	g.Lock()
	defer g.Unlock()
	return g.g.Join(sub, role)
}

// Leave implements Grouping interface
func (g *syncedGrouping) Leave(sub Subject, role Role) error {
	g.Lock()
	defer g.Unlock()
	return g.g.Leave(sub, role)
}

//  IsIn implements Grouping interface
func (g *syncedGrouping) IsIn(user User, role Role) (bool, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.IsIn(user, role)
}

//  AllRoles implements Grouping interface
func (g *syncedGrouping) AllRoles() (map[Role]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.AllRoles()
}

// AllUsers implements Grouping interface
func (g *syncedGrouping) AllUsers() (map[User]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.AllUsers()
}

// RolesOf implements Grouping interface
func (g *syncedGrouping) RolesOf(user User) (map[Role]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.RolesOf(user)
}

// UsersOf implements Grouping interface
func (g *syncedGrouping) UsersOf(role Role) (map[User]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.UsersOf(role)
}

//  DirectRolesOf implements Grouping interface
func (g *syncedGrouping) DirectRolesOf(sub Subject) (map[Role]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.DirectRolesOf(sub)
}

// DirectSubjectsOf implements Grouping interface
func (g *syncedGrouping) DirectSubjectsOf(role Role) (map[Subject]struct{}, error) {
	g.RLock()
	defer g.RUnlock()
	return g.g.DirectSubjectsOf(role)
}

// RemoveRole implements Grouping interface
func (g *syncedGrouping) RemoveRole(role Role) error {
	g.Lock()
	defer g.Unlock()
	return g.g.RemoveRole(role)
}

// RemoveUser implements Grouping interface
func (g *syncedGrouping) RemoveUser(user User) error {
	g.Lock()
	defer g.Unlock()
	return g.g.RemoveUser(user)
}
