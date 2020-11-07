package rbac

import "github.com/supremind/rbac/types"

// PublicShared specify that everbody could do act on obj
func PublicShared(obj types.Object, act types.Action) types.PresetPolicy {
	return func(authz types.Authorizer, _ types.Subject, ro types.Object, ra types.Action) bool {
		if act.Includes(ra) {
			if obj == ro {
				return true
			}
			if authz.Objects() != nil {
				if cat, ok := obj.(types.Category); ok {
					if art, ok := ro.(types.Article); ok {
						if in, e := authz.Objects().IsIn(art, cat); e == nil {
							return in
						}
					}
				}
			}
		}

		return false
	}
}

// SuperUser can do any action on anything
func SuperUser(su types.Subject) types.PresetPolicy {
	return func(authz types.Authorizer, rs types.Subject, _ types.Object, _ types.Action) bool {
		if rs == su {
			return true
		}
		if authz.Subjects() != nil {
			if role, ok := su.(types.Role); ok {
				if user, ok := rs.(types.User); ok {
					if in, e := authz.Subjects().IsIn(user, role); e == nil {
						return in
					}
				}
			}
		}

		return false
	}
}
