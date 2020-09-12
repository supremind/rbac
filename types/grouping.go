package types

// Grouping defines member-group relationships,
// an member could belong to any number of groups,
// and a group could contain any individuals or other groups.
type Grouping interface {
	GroupingWriter
	GroupingReader
}

// GroupingReader defines read methods used for grouping polices
type GroupingReader interface {
	// IsIn returns true if Member is a member of Group or members of Group
	IsIn(Member, Group) (bool, error)

	// AllGroups returns all Group have ever seen
	AllGroups() (map[Group]struct{}, error)

	// AllIndividuals returns all Individuals have ever seen
	AllIndividuals() (map[Member]struct{}, error)

	// IndividualsIn returns all individuals belongs to Group or sub Groups of Group
	IndividualsIn(Group) (map[Member]struct{}, error)

	// GroupsOf returns all groups the Entity or its Groups belongs to
	GroupsOf(Entity) (map[Group]struct{}, error)

	// ImmediateEntitiesIn returns Entities immediately belongs to Group
	ImmediateEntitiesIn(Group) (map[Entity]struct{}, error)

	// ImmediateGroupsOf returns groups the Entity immediately belongs to
	ImmediateGroupsOf(Entity) (map[Group]struct{}, error)
}

// GroupingWriter defines write methods used for grouping polices
type GroupingWriter interface {
	// Join an Entity to a Group, the Entity will "immediately" belongs to the Group
	Join(Entity, Group) error

	// Leave removes an Entity from a Group, the Entity will no longer belongs to the Group
	Leave(Entity, Group) error

	// RemoveGroup removes a Group, and all relationships about it
	RemoveGroup(Group) error

	// RemoveIndividual removes an Member, and all relationships about it
	RemoveIndividual(Member) error
}

// Entity is anything could be grouped together, or be a group of other entities
type Entity interface{}

// Group is an collection of entities
type Group interface {
	Entity
	group() string
}

// Member is an entity could be grouped together
type Member interface {
	Entity
	member() string
}

// User is an Member belongs to some Roles, and a Subject in Permissions
type User string

func (u User) String() string {
	return "user:" + string(u)
}

func (u User) member() string {
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

// Article is an Member belongs to some Categories, and an Object in Permissions
type Article string

func (a Article) String() string {
	return "art:" + string(a)
}

func (a Article) member() string {
	return a.String()
}

// Category is a Group of Articles, and an Object in Permissions
type Category string

func (c Category) String() string {
	return "cat:" + string(c)
}

func (c Category) group() string {
	return c.String()
}
