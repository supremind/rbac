package rbac

import (
	"context"
	"fmt"

	"github.com/supremind/rbac/internal/decision"
	"github.com/supremind/rbac/internal/grouping"
	"github.com/supremind/rbac/internal/permission"
	"github.com/supremind/rbac/types"
)

// New creates a RBAC DecisionMaker
func New(ctx context.Context, opts ...DecisionMakerOption) (types.DecisionMaker, error) {
	cfg := &decisionMakerConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	var sg, og types.Grouping
	if cfg.sp != nil {
		var e error
		sg, e = grouping.NewPersistedGrouping(ctx, grouping.NewSyncedGrouping(grouping.NewFatGrouping()), cfg.sp)
		if e != nil {
			return nil, fmt.Errorf("init subject grouping failed: %w", e)
		}
	}
	if cfg.op != nil {
		var e error
		og, e = grouping.NewPersistedGrouping(ctx, grouping.NewSyncedGrouping(grouping.NewFatGrouping()), cfg.op)
		if e != nil {
			return nil, fmt.Errorf("init object grouping failed: %w", e)
		}
	}

	var p types.Permission = permission.NewSyncedPermission(permission.NewThinPermission())
	if cfg.pp != nil {
		var e error
		p, e = permission.NewPersistedPermission(ctx, p, cfg.pp)
		if e != nil {
			return nil, fmt.Errorf("init permission failed: %w", e)
		}
	}
	if sg != nil && og != nil {
		p = permission.NewBothGroupedPermission(sg, og, p)
	}
	if sg != nil && og == nil {
		p = permission.NewSubjectGroupedPermission(sg, p)
	}
	if sg == nil && og != nil {
		p = permission.NewObjectGroupedPermission(og, p)
	}

	dm := decision.NewSyncedDecisionMaker(decision.NewDecisionMaker(sg, og, p))
	return dm, nil
}

// WithSubjectPersister sets Persister for subject
// could be omitted if subject grouping is not used: no roles, only users
func WithSubjectPersister(p types.GroupingPersister) DecisionMakerOption {
	return func(cfg *decisionMakerConfig) {
		cfg.sp = p
	}
}

// WithObjectPersister sets Persister for object
// could be omitted if object grouping is not used: no rules on categories
func WithObjectPersister(p types.GroupingPersister) DecisionMakerOption {
	return func(cfg *decisionMakerConfig) {
		cfg.op = p
	}
}

// WithPermissionPersister sets Persister for Permission manager
// all permission polices will be lost after restart if not set
func WithPermissionPersister(p types.PermissionPersister) DecisionMakerOption {
	return func(cfg *decisionMakerConfig) {
		cfg.pp = p
	}
}

type decisionMakerConfig struct {
	sp types.GroupingPersister
	op types.GroupingPersister
	pp types.PermissionPersister
}

// DecisionMakerOption controls how to init a decision maker
type DecisionMakerOption func(*decisionMakerConfig)
