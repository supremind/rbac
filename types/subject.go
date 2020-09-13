package types

import "strings"

// Subject is a User or a Role to perform actions on Objects
// Subject is not expecting custom implementations
type Subject interface {
	Entity
	subject() string
}

// User is a Member belongs to some Roles, and a subject in permissions
type User string

func (u User) String() string {
	return "user:" + string(u)
}

func (u User) member() string {
	return u.String()
}

func (u User) subject() string {
	return u.String()
}

// Role is a Group of Users, and a Subject in Permissions
type Role string

func (r Role) String() string {
	return "role:" + string(r)
}

func (r Role) group() string {
	return r.String()
}

func (r Role) subject() string {
	return r.String()
}

// ParseSubject parses an serialized Subject
func ParseSubject(s string) (Subject, error) {
	switch {
	case strings.HasPrefix(s, "user:"):
		return User(strings.TrimPrefix(s, "user:")), nil
	case strings.HasPrefix(s, "role:"):
		return Role(strings.TrimPrefix(s, "role:")), nil
	}

	return nil, ErrInvalidEntity
}
