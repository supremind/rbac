package rbac

type Object interface {
	Object() string
}

type Resource struct{}

type Category struct{}

type Objector interface {
	Categorize(Resource, Category) error
	Categories(Resource) ([]Category, error)
	Resources(Category) ([]Resource, error)
}
