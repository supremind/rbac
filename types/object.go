package types

// Object is an Article or a Category to perform actions on
// Object is not expecting custom implementations
type Object interface {
	object() string
}

// Article is an Member belongs to some Categories, and an Object in Permissions
type Article string

func (a Article) String() string {
	return "art:" + string(a)
}

func (a Article) member() string {
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
