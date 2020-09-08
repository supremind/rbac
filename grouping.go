package rbac

import (
	"strings"
)

type Subject interface {
	subject() string
}

type Grouping interface {
	Join(Subject, Role) error
	Leave(Subject, Role) error

	AllUsers() ([]User, error)
	AllRoles() ([]Role, error)

	RolesOf(Subject) ([]Role, error)
	UsersOf(Subject) ([]User, error)
	HasRole(Subject, Role) (bool, error)

	RemoveRole(Role) error
	RemoveUser(User) error
}

type User string

func (u User) subject() string {
	return "user:" + string(u)
}

func (u *User) parseSubject(s string) error {
	if strings.HasPrefix(s, "user:") {
		su := s[5:]
		*u = User(su)
		return nil
	}
	return ErrNotAUser
}

type Role string

var _ Subject = Role("")

func (r Role) subject() string {
	return "role:" + string(r)
}

func (r *Role) parseSubject(s string) error {
	if strings.HasPrefix(s, "role:") {
		su := s[5:]
		*r = Role(su)
		return nil
	}
	return ErrNotARole
}
