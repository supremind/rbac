package permission

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/houz42/rbac/types"
)

// New creates a concurent safe, persisted permission
func New(ctx context.Context, pp types.PermissionPersister, l logr.Logger) (types.Permission, error) {
	return newPersistedPermission(ctx, newThinPermission(), pp, l)
}
