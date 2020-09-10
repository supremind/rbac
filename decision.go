package rbac

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

func NewDecisionMaker(opts ...DecisionMakerOption) DecisionMaker {
	dm := &decisionMaker{
		uap: make(map[User]map[Article]Action),
	}

	cfg := &decisionMakerConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.subjectsGrouped {
		dm.sg = newFatGrouping()
		if cfg.synced {
			dm.sg = newSyncedGrouping(dm.sg)
		}
	}
	if cfg.objectsGrouped {
		dm.og = newFatGrouping()
		if cfg.synced {
			dm.og = newSyncedGrouping(dm.og)
		}
	}

	dm.p = newThinPermission()
	if dm.sg != nil {
		if dm.og != nil {
			dm.p = newBothGroupedPermission(dm.sg, dm.og, dm.p)
		} else {
			dm.p = newSubjectGroupedPermission(dm.sg, dm.p)
		}
	} else {
		if dm.og != nil {
			dm.p = newObjectGroupedPermission(dm.og, dm.p)
		}
	}
	if cfg.synced {
		dm.p = newSyncedPermission(dm.p)
		return newSyncedDecisionMaker(dm)
	}

	return dm
}

type decisionMakerConfig struct {
	synced          bool
	subjectsGrouped bool
	objectsGrouped  bool
}

type DecisionMakerOption func(*decisionMakerConfig)

func WithSubjectGrouping() DecisionMakerOption {
	return func(c *decisionMakerConfig) {
		c.subjectsGrouped = true
	}
}

func WithObjectGrouping() DecisionMakerOption {
	return func(c *decisionMakerConfig) {
		c.objectsGrouped = true
	}
}

func WithSynced() DecisionMakerOption {
	return func(c *decisionMakerConfig) {
		c.synced = true
	}
}
