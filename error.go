package rbac

import "errors"

var (
	ErrNotFound          = errors.New("not found")
	ErrInvlaidSubject    = errors.New("invalid subject, it should be a User or Role")
	ErrInvlaidObject     = errors.New("invalid object, it should be an Article or Category")
	ErrNoSubjectGrouping = errors.New("subject grouping is not configured")
	ErrNoObjectGrouping  = errors.New("object grouping is not configured")
	ErrUnsupportedChange = errors.New("persister changes in a way unsupported")
)
