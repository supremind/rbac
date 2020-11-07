package authorizer

import "github.com/supremind/rbac/types"

type authorizerWithPreset struct {
	presets []types.PresetPolicy
	types.Authorizer
}

func newWithPresetPolices(authz types.Authorizer, presets ...types.PresetPolicy) *authorizerWithPreset {
	return &authorizerWithPreset{
		presets:    presets,
		Authorizer: authz,
	}
}

func (a *authorizerWithPreset) Shall(sub types.Subject, obj types.Object, act types.Action) (bool, error) {
	for _, p := range a.presets {
		if p(a, sub, obj, act) {
			return true, nil
		}
	}

	return a.Authorizer.Shall(sub, obj, act)
}
