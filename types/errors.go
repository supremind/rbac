package types

import "errors"

// exported errors
var (
	ErrNotFound          = errors.New("not found")
	ErrInvalidEntity     = errors.New("invlid entity, it should be one of user, role, article, and catetory")
	ErrInvalidGroup      = errors.New("invalid group, it should be a role or a catetory")
	ErrInvalidMember     = errors.New("invalid member, it should be a user or an article")
	ErrInvlaidSubject    = errors.New("invalid subject, it should be a User or Role")
	ErrInvlaidObject     = errors.New("invalid object, it should be an Article or Category")
	ErrNoSubjectGrouping = errors.New("subject grouping is not configured")
	ErrNoObjectGrouping  = errors.New("object grouping is not used")
	ErrUnsupportedChange = errors.New("persister changes in a way used")
	ErrUnknownAction     = errors.New("unknown action")
)
