package rbac

import "errors"

var ErrNotAUser = errors.New("subject is not a user")
var ErrNotARole = errors.New("subject is not a role")
var ErrNotFound = errors.New("not found")
