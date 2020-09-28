package grouping

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/houz42/rbac/types"
)

// New creates a concurent safe, persisted grouping
func New(ctx context.Context, gp types.GroupingPersister, l logr.Logger) (types.Grouping, error) {
	g, e := newPersistedGrouping(ctx, newFatGrouping(), gp, l)
	if e != nil {
		return nil, e
	}
	return newSyncedGrouping(g), nil
}
