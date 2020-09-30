package types

import "strings"

// Grouping defines member-group relationships,
// an member could belong to any number of groups,
// and a group could contain any members or other groups.
type Grouping interface {
	GroupingWriter
	GroupingReader
}

// GroupingReader defines methods to get grouping assignment polices
type GroupingReader interface {
	// IsIn returns true if Member is a member of Group or members of Group
	IsIn(Member, Group) (bool, error)

	// AllGroups returns all Group have ever seen
	AllGroups() (map[Group]struct{}, error)

	// AllMembers returns all members have ever seen
	AllMembers() (map[Member]struct{}, error)

	// MembersIn returns all members belongs to Group or sub Groups of Group
	MembersIn(Group) (map[Member]struct{}, error)

	// GroupsOf returns all groups the member belongs to
	GroupsOf(Entity) (map[Group]struct{}, error)
}

// GroupingWriter defines methods to create, update, or remove grouping assignment polices
type GroupingWriter interface {
	// Join an Entity to a Group, the Entity will "immediately" belongs to the Group
	Join(Entity, Group) error

	// Leave removes an Entity from a Group, the Entity will no longer belongs to the Group
	Leave(Entity, Group) error

	// RemoveGroup removes a Group, and all relationships about it
	RemoveGroup(Group) error

	// RemoveMember removes an Member, and all relationships about it
	RemoveMember(Member) error
}

// Entity is anything could be grouped together, or be a group of other entities
type Entity interface {
	// String method is used to be serialized when persisting
	String() string
}

// Group is an collection of entities, like Role in user-role, or Category in article-cagetory relationships
// Group is not expecting custom implementations
type Group interface {
	Entity
	group() string
}

// Member is an entity could be grouped together, like User in user-role, or Article in article-cagetory relationships
// Member is not expecting custom implementations
type Member interface {
	Entity
	member() string
}

// ParseEntity parses an serialized Entity
func ParseEntity(s string) (Entity, error) {
	switch {
	case strings.HasPrefix(s, "user:"):
		return User(strings.TrimPrefix(s, "user:")), nil
	case strings.HasPrefix(s, "role:"):
		return Role(strings.TrimPrefix(s, "role:")), nil
	case strings.HasPrefix(s, "art:"):
		return Article(strings.TrimPrefix(s, "art:")), nil
	case strings.HasPrefix(s, "cat:"):
		return Category(strings.TrimPrefix(s, "cat:")), nil
	}

	return nil, ErrInvalidEntity
}

// ParseGroup parse a serialized Group
func ParseGroup(s string) (Group, error) {
	switch {
	case strings.HasPrefix(s, "role:"):
		return Role(strings.TrimPrefix(s, "role:")), nil
	case strings.HasPrefix(s, "cat:"):
		return Category(strings.TrimPrefix(s, "cat:")), nil
	}

	return nil, ErrInvalidEntity
}

// ParseMember parses a serialized Member
func ParseMember(s string) (Member, error) {
	switch {
	case strings.HasPrefix(s, "user:"):
		return User(strings.TrimPrefix(s, "user:")), nil
	case strings.HasPrefix(s, "art:"):
		return Article(strings.TrimPrefix(s, "art:")), nil
	}

	return nil, ErrInvalidMember
}
