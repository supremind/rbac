package mgo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/globalsign/mgo"
	"github.com/houz42/rbac/types"
)

// GroupingPersister is a GroupingPersister backed by mongodb
type GroupingPersister struct {
	*collection
}

// NewGrouping uses the given mongodb collection as backend to persist grouping polices
func NewGrouping(coll *mgo.Collection, opts ...collectionOption) (*GroupingPersister, error) {
	c := &GroupingPersister{&collection{Collection: coll}}
	for _, opt := range opts {
		opt(c.collection)
	}

	ss := c.copySession()
	defer ss.closeSession()

	if e := ss.EnsureIndex(mgo.Index{Key: []string{"entity", "group"}, Unique: true}); e != nil {
		return nil, e
	}

	return c, nil
}

type groupingPolicyDO struct {
	ID     string `bson:"_id"`
	Entity entity `bson:"entity,omitempty"`
	Group  group  `bson:"group,omitempty"`
}

func newGroupingPolicyDO(ent types.Entity, grp types.Group) *groupingPolicyDO {
	p := &groupingPolicyDO{}

	switch ent.(type) {
	case types.User:
		p.Entity.User = ent.(types.User)
	case types.Role:
		p.Entity.Role = ent.(types.Role)
	case types.Article:
		p.Entity.Article = ent.(types.Article)
	case types.Category:
		p.Entity.Category = ent.(types.Category)
	}

	switch grp.(type) {
	case types.Role:
		p.Group.Role = grp.(types.Role)
	case types.Category:
		p.Group.Category = grp.(types.Category)
	}

	p.ID = p.id()

	return p
}

func (p *groupingPolicyDO) id() string {
	return p.Entity.String() + "#" + p.Group.String()
}

func (p *groupingPolicyDO) parseID(id string) error {
	parts := strings.SplitN(id, "#", 2)
	if len(parts) < 2 {
		return fmt.Errorf("invalid grouping policy id: %s", id)
	}

	ent, grp := parts[0], parts[1]
	entity, e := types.ParseEntity(ent)
	if e != nil {
		return nil
	}
	switch entity.(type) {
	case types.User:
		p.Entity.User = entity.(types.User)
	case types.Role:
		p.Entity.Role = entity.(types.Role)
	case types.Article:
		p.Entity.Article = entity.(types.Article)
	case types.Category:
		p.Entity.Category = entity.(types.Category)
	}

	group, e := types.ParseGroup(grp)
	if e != nil {
		return e
	}
	switch group.(type) {
	case types.Role:
		p.Group.Role = group.(types.Role)
	case types.Category:
		p.Group.Category = group.(types.Category)
	}

	return nil
}

func (p *groupingPolicyDO) asGroupingPolicy() types.GroupingPolicy {
	gp := types.GroupingPolicy{}

	switch {
	case p.Entity.User != "":
		gp.Entity = p.Entity.User
	case p.Entity.Role != "":
		gp.Entity = p.Entity.Role
	case p.Entity.Article != "":
		gp.Entity = p.Entity.Article
	case p.Entity.Category != "":
		gp.Entity = p.Entity.Category
	}

	switch {
	case p.Group.Role != "":
		gp.Group = p.Group.Role
	case p.Group.Category != "":
		gp.Group = p.Group.Category
	}

	return gp
}

type entity struct {
	// exactly one of these field should be set
	User     types.User     `bson:"user,omitempty"`
	Role     types.Role     `bson:"role,omitempty"`
	Article  types.Article  `bson:"article,omitempty"`
	Category types.Category `bson:"category,omitempty"`
}

func (e *entity) String() string {
	switch {
	case e.User != "":
		return e.User.String()
	case e.Role != "":
		return e.Role.String()
	case e.Article != "":
		return e.Article.String()
	case e.Category != "":
		return e.Category.String()
	}
	return ""
}

type group struct {
	// exactly one of these field should be set
	Role     types.Role     `bson:"role,omitempty"`
	Category types.Category `bson:"category,omitempty"`
}

func (g group) String() string {
	switch {
	case g.Role != "":
		return g.Role.String()
	case g.Category != "":
		return g.Category.String()
	}
	return ""
}

// Insert inserts a policy to the persister
func (p *GroupingPersister) Insert(ent types.Entity, group types.Group) error {
	ss := p.copySession()
	defer ss.closeSession()

	policy := newGroupingPolicyDO(ent, group)
	p.log.V(4).Info("insert group policy", "policy", policy)

	return ss.Insert(policy)
}

// Remove a policy from the persister
func (p *GroupingPersister) Remove(ent types.Entity, group types.Group) error {
	ss := p.copySession()
	defer ss.closeSession()

	policy := newGroupingPolicyDO(ent, group)
	p.log.V(4).Info("remove group policy", "policy", policy)

	return parseMgoError(ss.RemoveId(policy.ID))
}

// List all policies from the persister
func (p *GroupingPersister) List() ([]types.GroupingPolicy, error) {
	ss := p.copySession()
	defer ss.closeSession()

	iter := ss.Find(nil).Iter()
	defer iter.Close()

	polices := make([]types.GroupingPolicy, 0)

	var gp groupingPolicyDO
	for iter.Next(&gp) {
		polices = append(polices, gp.asGroupingPolicy())
		gp = groupingPolicyDO{}
	}
	if e := iter.Err(); e != nil {
		return nil, e
	}

	p.log.V(4).Info("list grouping policies", "polices", polices)

	return polices, nil
}

type groupingChangeEvent struct {
	OperationType changeStreamOperationType `bson:"operationType,omitempty"`
	FullDocument  groupingPolicyDO          `bson:"fullDocument,omitempty"`
	DocumentKey   struct {
		ID string `bson:"_id,omitempty"`
	} `bson:"documentKey,omitempty"`
	UpdateDescription struct {
		UpdatedFields map[string]string `bson:"updatedFields,omitempty"`
	} `bson:"updateDescription,omitempty"`
}

// Watch any changes occurred about the policies in the persister
func (p *GroupingPersister) Watch(ctx context.Context) (<-chan types.GroupingPolicyChange, error) {
	connect := func() (*mgo.ChangeStream, func(), error) {
		ss := p.copySession()
		cs, e := ss.Watch(nil, mgo.ChangeStreamOptions{
			FullDocument: mgo.UpdateLookup,
		})
		if e != nil {
			return nil, nil, e
		}

		p.log.Info("watch mongo stream change")

		return cs, func() {
			cs.Close()
			ss.closeSession()
		}, nil
	}

	fetch := func(cs *mgo.ChangeStream, changes chan<- types.GroupingPolicyChange) error {
		for {
			var event groupingChangeEvent
			if cs.Next(&event) {
				var method types.PersistMethod

				switch event.OperationType {
				case insert:
					method = types.PersistInsert
				case update:
					method = types.PersistUpdate
					// returned fulldocument is queried after updating, may not be the same as which intended to update to
					// and even be deleted already
					policy := groupingPolicyDO{}
					if e := policy.parseID(event.DocumentKey.ID); e != nil {
						p.log.Error(e, "parse grouping policy do id", "id", event.DocumentKey.ID)
						continue
					}
					event.FullDocument = policy

				case delete:
					method = types.PersistDelete
					// we cannot get fulldocument if deleted, and have to parse it from id
					policy := groupingPolicyDO{}
					if e := policy.parseID(event.DocumentKey.ID); e != nil {
						p.log.Error(e, "parse grouping policy do id", "id", event.DocumentKey.ID)
						continue
					}
					event.FullDocument = policy

				default:
					p.log.Info("unknown operation type", "operation type", event.OperationType, "document", event.FullDocument)
					continue
				}

				p.log.V(4).Info("got grouping change event", "method", method, "policy", event.FullDocument)
				policy := event.FullDocument.asGroupingPolicy()
				change := types.GroupingPolicyChange{
					GroupingPolicy: types.GroupingPolicy{
						Entity: policy.Entity,
						Group:  policy.Group,
					},
					Method: method,
				}

				select {
				case <-ctx.Done():
					close(changes)
					return ctx.Err()
				case changes <- change:
				}
			}

			if e := cs.Err(); e != nil {
				if errors.Is(e, mgo.ErrNotFound) {
					p.log.V(2).Info("watch found nothing, retry later")
					time.Sleep(p.retryTimeout)
					continue
				}

				return e
			}
		}
	}

	cs, closer, e := connect()
	if e != nil {
		return nil, e
	}
	firstConnect := true

	changes := make(chan types.GroupingPolicyChange)
	go func() {
		for {
			select {
			case <-ctx.Done():
				closer()
				return

			default:
				if !firstConnect {
					cs, closer, e = connect()
					if e != nil {
						p.log.Error(e, "connect to watch failed, reconnect later")
						time.Sleep(p.retryTimeout)
						continue
					}
				}

				firstConnect = false
				e := fetch(cs, changes)
				closer()
				if e != nil {
					p.log.Error(e, "fetch event change failed, reconnect later")
				}
				time.Sleep(p.retryTimeout)
			}
		}
	}()

	return changes, nil
}
