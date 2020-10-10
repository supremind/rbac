package rbac

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
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

	if cfg.log == nil {
		cfg.log = stdr.New(log.New(os.Stderr, "", log.LstdFlags|log.Lshortfile))
	}

	var sg, og types.Grouping
	if cfg.sp != nil {
		var e error
		sg, e = grouping.New(ctx, cfg.sp, cfg.log.WithName("subject"))
		if e != nil {
			return nil, fmt.Errorf("init subject grouping failed: %w", e)
		}
	}
	if cfg.op != nil {
		var e error
		og, e = grouping.New(ctx, cfg.op, cfg.log.WithName("object"))
		if e != nil {
			return nil, fmt.Errorf("init object grouping failed: %w", e)
		}
	}

	var p types.Permission
	if cfg.pp != nil {
		var e error
		p, e = permission.New(ctx, cfg.pp, cfg.log.WithName("permission"))
		if e != nil {
			return nil, fmt.Errorf("init permission failed: %w", e)
		}
	} else {
		return nil, errors.New("empty permission persister")
	}

	authz := authorizer.New(sg, og, p, cfg.presets...)

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

// WithPresetPolices add preset polices to authorizer
func WithPresetPolices(presets ...types.PresetPolicy) AuthorizerOption {
	return func(cfg *AuthorizerConfig) {
		cfg.presets = append(cfg.presets, presets...)
	}
}

// WithLogger sets logger for rbac components
func WithLogger(l logr.Logger) AuthorizerOption {
	return func(cfg *AuthorizerConfig) {
		cfg.log = l
	}
}

// AuthorizerConfig works together with AuthorizerOption to control the initialization of authorizer
type AuthorizerConfig struct {
	sp      types.GroupingPersister
	op      types.GroupingPersister
	pp      types.PermissionPersister
	presets []types.PresetPolicy
	log     logr.Logger
}

// AuthorizerOption controls how to init an authorizer
type AuthorizerOption func(*AuthorizerConfig)
