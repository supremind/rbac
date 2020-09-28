package permission

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/houz42/rbac/types"
)

// New creates a concurent safe, persisted permission
func New(ctx context.Context, p types.PermissionPersister, l logr.Logger) (types.Permission, error) {
	perm, e := newPersistedPermission(ctx, newThinPermission(), p, l)
	if e != nil {
		return nil, e
	}
	return newSyncedPermission(perm), nil
}
