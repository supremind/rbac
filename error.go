package rbac

import "errors"

var (
	ErrNotFound       = errors.New("not found")
	ErrInvlaidSubject = errors.New("invalid subject")
)
