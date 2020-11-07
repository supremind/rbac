package grouping

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/supremind/rbac/types"
)

// New creates a concurent safe, persisted grouping
func New(ctx context.Context, gp types.GroupingPersister, l logr.Logger) (types.Grouping, error) {
	return newPersistedGrouping(ctx, gp, l)
}

type grouping interface {
	types.Grouping

	// private methods to be used between private groupings

	// immediateEntitiesIn returns Entities immediately belongs to Group
	immediateEntitiesIn(types.Group) (map[types.Entity]struct{}, error)

	// immediateGroupsOf returns groups the Entity immediately belongs to
	immediateGroupsOf(types.Entity) (map[types.Group]struct{}, error)
}
