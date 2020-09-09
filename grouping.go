package rbac

import (
	"strings"
)

type Grouping interface {
	Join(Subject, Role) error
	Leave(Subject, Role) error

	IsIn(User, Role) (bool, error)

	AllRoles() (map[Role]struct{}, error)
	AllUsers() (map[User]struct{}, error)

	RolesOf(User) (map[Role]struct{}, error)
	UsersOf(Role) (map[User]struct{}, error)

	DirectRolesOf(Subject) (map[Role]struct{}, error)
	DirectSubjectsOf(Role) (map[Subject]struct{}, error)

	RemoveRole(Role) error
	RemoveUser(User) error
}

type Subject interface {
	subject() string
}

type User string

func (u User) subject() string {
	return "user:" + string(u)
}

type Role string

func (r Role) subject() string {
	return "role:" + string(r)
}

func ParseSubject(sub string) (Subject, error) {
	if strings.HasPrefix(sub, "user:") {
		u := strings.TrimPrefix(sub, "user:")
		return User(u), nil
	}
	if strings.HasPrefix(sub, "role:") {
		r := strings.TrimPrefix(sub, "role:")
		return Role(r), nil
	}

	return nil, ErrInvlaidSubject
}
