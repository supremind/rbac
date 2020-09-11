package types

type DecisionMaker interface {
	Subjector
	Objector
	Permission
}

// Subjector manages subjects and groupings of subjects
type Subjector interface {
	// SubjectJoin joins a user or a sub role to a role
	SubjectJoin(sub Subject, role Role) error
	// SubjectLeave removes a user or a sub role from a role
	SubjectLeave(sub Subject, role Role) error
	// RemoveUser removes a user and all policies about it
	RemoveUser(user User) error
	// RemoveRole removes a role and all policies about it
	RemoveRole(role Role) error
	// Subjects returns the GroupingReader interface for subjects
	Subjects() GroupingReader
}

// Objector manages objects and groupings of objects
type Objector interface {
	// ObjectJoin joins an article or a sub category to a category
	ObjectJoin(obj Object, cat Category) error
	// ObjectLeave removes an article or a sub category from a category
	ObjectLeave(obj Object, cat Category) error
	// RemoveArticle removes an article and all polices about it
	RemoveArticle(art Article) error
	// RemoveCategory removes a category and all polices about it
	RemoveCategory(cat Category) error
	// Objects returns the GroupingReader interface for objects
	Objects() GroupingReader
}
