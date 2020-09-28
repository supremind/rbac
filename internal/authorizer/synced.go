package authorizer

import (
	"sync"

	"github.com/houz42/rbac/types"
)

var _ types.Authorizer = (*syncedAuthorizer)(nil)

// syncedAuthorizer makes the given authorizer be safe in concurrent usages
type syncedAuthorizer struct {
	sync.RWMutex
	authz types.Authorizer
}

func newSyncedAuthorizer(authz types.Authorizer) *syncedAuthorizer {
	return &syncedAuthorizer{authz: authz}
}

// SubjectJoin joins a user or a sub role to a role
func (authz *syncedAuthorizer) SubjectJoin(sub types.Subject, role types.Role) error {
	authz.Lock()
	defer authz.Unlock()

	return authz.authz.SubjectJoin(sub, role)
}

// SubjectLeave removes a user or a sub role from a role
func (authz *syncedAuthorizer) SubjectLeave(sub types.Subject, role types.Role) error {
	authz.Lock()
	defer authz.Unlock()

	return authz.authz.SubjectLeave(sub, role)
}

// RemoveUser removes a user and all policies about it
func (authz *syncedAuthorizer) RemoveUser(user types.User) error {
	authz.Lock()
	defer authz.Unlock()

	return authz.authz.RemoveUser(user)
}

// RemoveRole removes a role and all policies about it
func (authz *syncedAuthorizer) RemoveRole(role types.Role) error {
	authz.Lock()
	defer authz.Unlock()

	return authz.authz.RemoveRole(role)
}

// Subjects returns the types.GroupingReader interface for subjects
func (authz *syncedAuthorizer) Subjects() types.GroupingReader {
	return authz.authz.Subjects()
}

// ObjectJoin joins an article or a sub category to a category
func (authz *syncedAuthorizer) ObjectJoin(obj types.Object, cat types.Category) error {
	authz.Lock()
	defer authz.Unlock()

	return authz.authz.ObjectJoin(obj, cat)
}

// ObjectLeave removes an article or a sub category from a category
func (authz *syncedAuthorizer) ObjectLeave(obj types.Object, cat types.Category) error {
	authz.Lock()
	defer authz.Unlock()

	return authz.authz.ObjectLeave(obj, cat)
}

// RemoveArticle removes an article and all polices about it
func (authz *syncedAuthorizer) RemoveArticle(art types.Article) error {
	authz.Lock()
	defer authz.Unlock()

	return authz.authz.RemoveArticle(art)
}

// RemoveCategory removes a category and all polices about it
func (authz *syncedAuthorizer) RemoveCategory(cat types.Category) error {
	authz.Lock()
	defer authz.Unlock()

	return authz.authz.RemoveCategory(cat)
}

// Objects returns the types.GroupingReader interface for objects
func (authz *syncedAuthorizer) Objects() types.GroupingReader {
	return authz.authz.Objects()
}

// Permit subject to perform action on object
func (authz *syncedAuthorizer) Permit(sub types.Subject, obj types.Object, act types.Action) error {
	authz.Lock()
	defer authz.Unlock()

	return authz.authz.Permit(sub, obj, act)
}

// Revoke permission for subject to perform action on object
func (authz *syncedAuthorizer) Revoke(sub types.Subject, obj types.Object, act types.Action) error {
	authz.Lock()
	defer authz.Unlock()

	return authz.authz.Revoke(sub, obj, act)
}

// Shall subject to perform action on object
func (authz *syncedAuthorizer) Shall(sub types.Subject, obj types.Object, act types.Action) (bool, error) {
	authz.RLock()
	defer authz.RUnlock()

	return authz.authz.Shall(sub, obj, act)
}

// PermissionsOn object for all subjects
func (authz *syncedAuthorizer) PermissionsOn(obj types.Object) (map[types.Subject]types.Action, error) {
	authz.RLock()
	defer authz.RUnlock()

	return authz.authz.PermissionsOn(obj)
}

// PermissionsFor subject on all objects
func (authz *syncedAuthorizer) PermissionsFor(sub types.Subject) (map[types.Object]types.Action, error) {
	authz.RLock()
	defer authz.RUnlock()

	return authz.authz.PermissionsFor(sub)
}

// PermittedActions for subject on object
func (authz *syncedAuthorizer) PermittedActions(sub types.Subject, obj types.Object) (types.Action, error) {
	authz.RLock()
	defer authz.RUnlock()

	return authz.authz.PermittedActions(sub, obj)
}
