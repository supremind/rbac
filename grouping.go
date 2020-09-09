package rbac

// Grouper defines individual-group relationships,
// an individual could belong to any number of groups,
// and a group could contain any individuals or other groups.
type Grouper interface {
	Join(Entity, Group) error
	Leave(Entity, Group) error

	IsIn(Individual, Group) (bool, error)

	AllGroups() (map[Group]struct{}, error)
	AllIndividuals() (map[Individual]struct{}, error)

	IndividualsIn(Group) (map[Individual]struct{}, error)
	GroupsOf(Individual) (map[Group]struct{}, error)

	ImmediateEntitiesIn(Group) (map[Entity]struct{}, error)
	ImmediateGroupsOf(Entity) (map[Group]struct{}, error)

	RemoveGroup(Group) error
	RemoveIndividual(Individual) error
}

type Entity interface{}

type Group interface {
	Entity
	group() string
}

type Individual interface {
	Entity
	individual() string
}

type Subject interface {
	Entity
	subject() string
}

type Object interface {
	Entity
	object() string
}

// User is an Individual belongs to some Roles, and a Subject in Permissions
type User string

func (u User) String() string {
	return "user:" + string(u)
}

func (u User) individual() string {
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

// Article is an Individual belongs to some Categories, and an Object in Permissions
type Article string

func (a Article) String() string {
	return "art:" + string(a)
}

func (a Article) individual() string {
	return a.String()
}

func (a Article) object() string {
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

func (c Category) object() string {
	return c.String()
}
