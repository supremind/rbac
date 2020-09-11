package decision

import (
	"sync"

	. "github.com/supremind/rbac/types"
)

var _ DecisionMaker = (*syncedDecisionMaker)(nil)

type syncedDecisionMaker struct {
	sync.RWMutex
	dm DecisionMaker
}

func NewSyncedDecisionMaker(dm DecisionMaker) *syncedDecisionMaker {
	return &syncedDecisionMaker{dm: dm}
}

// SubjectJoin joins a user or a sub role to a role
func (dm *syncedDecisionMaker) SubjectJoin(sub Subject, role Role) error {
	dm.Lock()
	defer dm.Unlock()

	return dm.dm.SubjectJoin(sub, role)
}

// SubjectLeave removes a user or a sub role from a role
func (dm *syncedDecisionMaker) SubjectLeave(sub Subject, role Role) error {
	dm.Lock()
	defer dm.Unlock()

	return dm.dm.SubjectLeave(sub, role)
}

// RemoveUser removes a user and all policies about it
func (dm *syncedDecisionMaker) RemoveUser(user User) error {
	dm.Lock()
	defer dm.Unlock()

	return dm.dm.RemoveUser(user)
}

// RemoveRole removes a role and all policies about it
func (dm *syncedDecisionMaker) RemoveRole(role Role) error {
	dm.Lock()
	defer dm.Unlock()

	return dm.dm.RemoveRole(role)
}

// Subjects returns the GroupingReader interface for subjects
func (dm *syncedDecisionMaker) Subjects() GroupingReader {
	return dm.dm.Subjects()
}

// ObjectJoin joins an article or a sub category to a category
func (dm *syncedDecisionMaker) ObjectJoin(obj Object, cat Category) error {
	dm.Lock()
	defer dm.Unlock()

	return dm.dm.ObjectJoin(obj, cat)
}

// ObjectLeave removes an article or a sub category from a category
func (dm *syncedDecisionMaker) ObjectLeave(obj Object, cat Category) error {
	dm.Lock()
	defer dm.Unlock()

	return dm.dm.ObjectLeave(obj, cat)
}

// RemoveArticle removes an article and all polices about it
func (dm *syncedDecisionMaker) RemoveArticle(art Article) error {
	dm.Lock()
	defer dm.Unlock()

	return dm.dm.RemoveArticle(art)
}

// RemoveCategory removes a category and all polices about it
func (dm *syncedDecisionMaker) RemoveCategory(cat Category) error {
	dm.Lock()
	defer dm.Unlock()

	return dm.dm.RemoveCategory(cat)
}

// Objects returns the GroupingReader interface for objects
func (dm *syncedDecisionMaker) Objects() GroupingReader {
	return dm.dm.Objects()
}

// Permit subject to perform action on object
func (dm *syncedDecisionMaker) Permit(sub Subject, obj Object, act Action) error {
	dm.Lock()
	defer dm.Unlock()

	return dm.dm.Permit(sub, obj, act)
}

// Revoke permission for subject to perform action on object
func (dm *syncedDecisionMaker) Revoke(sub Subject, obj Object, act Action) error {
	dm.Lock()
	defer dm.Unlock()

	return dm.dm.Revoke(sub, obj, act)
}

// Shall subject to perform action on object
func (dm *syncedDecisionMaker) Shall(sub Subject, obj Object, act Action) (bool, error) {
	dm.RLock()
	defer dm.RUnlock()

	return dm.dm.Shall(sub, obj, act)
}

// PermissionsOn object for all subjects
func (dm *syncedDecisionMaker) PermissionsOn(obj Object) (map[Subject]Action, error) {
	dm.RLock()
	defer dm.RUnlock()

	return dm.dm.PermissionsOn(obj)
}

// PermissionsFor subject on all objects
func (dm *syncedDecisionMaker) PermissionsFor(sub Subject) (map[Object]Action, error) {
	dm.RLock()
	defer dm.RUnlock()

	return dm.dm.PermissionsFor(sub)
}

// PermittedActions for subject on object
func (dm *syncedDecisionMaker) PermittedActions(sub Subject, obj Object) (Action, error) {
	dm.RLock()
	defer dm.RUnlock()

	return dm.dm.PermittedActions(sub, obj)
}
