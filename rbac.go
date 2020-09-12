package rbac

import (
	"context"
	"fmt"

	"github.com/houz42/rbac/internal/authorizer"
	"github.com/houz42/rbac/internal/grouping"
	"github.com/houz42/rbac/internal/permission"
	"github.com/houz42/rbac/types"
)

// New creates a RBAC Authorizer
func New(ctx context.Context, opts ...AuthorizerOption) (types.Authorizer, error) {
	cfg := &AuthorizerConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	var sg, og types.Grouping
	if cfg.sp != nil {
		var e error
		sg, e = grouping.NewPersistedGrouping(ctx, nil, cfg.sp)
		if e != nil {
			return nil, fmt.Errorf("init subject grouping failed: %w", e)
		}
	}
	if cfg.op != nil {
		var e error
		og, e = grouping.NewPersistedGrouping(ctx, nil, cfg.op)
		if e != nil {
			return nil, fmt.Errorf("init object grouping failed: %w", e)
		}
	}

	var p types.Permission = permission.NewSyncedPermission(nil)
	if cfg.pp != nil {
		var e error
		p, e = permission.NewPersistedPermission(ctx, p, cfg.pp)
		if e != nil {
			return nil, fmt.Errorf("init permission failed: %w", e)
		}
	}
	if sg != nil && og != nil {
		p = authorizer.NewBothGroupedPermission(sg, og, p)
	}
	if sg != nil && og == nil {
		p = authorizer.NewSubjectGroupedPermission(sg, p)
	}
	if sg == nil && og != nil {
		p = authorizer.NewObjectGroupedPermission(og, p)
	}

	authz := authorizer.NewSyncedAuthorizer(authorizer.NewAuthorizer(sg, og, p))
	return authz, nil
}

// WithSubjectPersister sets Persister for subject
// could be omitted if subject grouping is not used: no roles, only users
func WithSubjectPersister(p types.GroupingPersister) AuthorizerOption {
	return func(cfg *AuthorizerConfig) {
		cfg.sp = p
	}
}

// WithObjectPersister sets Persister for object
// could be omitted if object grouping is not used: no rules on categories
func WithObjectPersister(p types.GroupingPersister) AuthorizerOption {
	return func(cfg *AuthorizerConfig) {
		cfg.op = p
	}
}

// WithPermissionPersister sets Persister for Permission manager
// all permission polices will be lost after restart if not set
func WithPermissionPersister(p types.PermissionPersister) AuthorizerOption {
	return func(cfg *AuthorizerConfig) {
		cfg.pp = p
	}
}

type AuthorizerConfig struct {
	sp types.GroupingPersister
	op types.GroupingPersister
	pp types.PermissionPersister
}

// AuthorizerOption controls how to init a authorizer
type AuthorizerOption func(*AuthorizerConfig)
