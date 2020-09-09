package rbac

import "sync"

var _ Grouping = (*syncedGrouping)(nil)

// syncedGrouping is safe in concurrent usages
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
