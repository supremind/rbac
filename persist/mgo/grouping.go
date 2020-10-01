package mgo

import (
	"context"
	"errors"
	"time"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
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

	return c, nil
}

type groups struct {
	Entity  entity  `bson:"_id"`
	Groups  []group `bson:"groups"`
	Deleted []group `bson:"deleted"`
}

type entity struct {
	// exactly one of these field should be set
	User     types.User     `bson:"user,omitempty"`
	Role     types.Role     `bson:"role,omitempty"`
	Article  types.Article  `bson:"article,omitempty"`
	Category types.Category `bson:"category,omitempty"`
}

func fromEntity(ent types.Entity) entity {
	e := entity{}
	switch ent.(type) {
	case types.User:
		e.User = ent.(types.User)
	case types.Role:
		e.Role = ent.(types.Role)
	case types.Article:
		e.Article = ent.(types.Article)
	case types.Category:
		e.Category = ent.(types.Category)
	}

	return e
}

func (e *entity) asEntity() types.Entity {
	var ent types.Entity

	switch {
	case e.User != "":
		ent = e.User
	case e.Role != "":
		ent = e.Role
	case e.Article != "":
		ent = e.Article
	case e.Category != "":
		ent = e.Category
	}

	return ent
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

func (e *entity) SetBSON(raw bson.Raw) error {
	var s string
	if e := raw.Unmarshal(&s); e != nil {
		return e
	}

	ent, err := types.ParseEntity(s)
	if err != nil {
		return err
	}

	*e = fromEntity(ent)
	return nil
}

type group struct {
	// exactly one of these field should be set
	Role     types.Role     `bson:"role,omitempty"`
	Category types.Category `bson:"category,omitempty"`
}

func fromGroup(grp types.Group) group {
	g := group{}

	switch grp.(type) {
	case types.Role:
		g.Role = grp.(types.Role)
	case types.Category:
		g.Category = grp.(types.Category)
	}

	return g
}

func (g group) asGroup() types.Group {
	var grp types.Group

	switch {
	case g.Role != "":
		grp = g.Role
	case g.Category != "":
		grp = g.Category
	}

	return grp
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

func (g *group) SetBSON(raw bson.Raw) error {
	obj := make(map[string]string, 1)
	if e := raw.Unmarshal(&obj); e != nil {
		return e
	}

	if len(obj) != 1 {
		return nil
	}

	for key, val := range obj {
		switch key {
		case "role":
			g.Role = types.Role(val)
		case "category":
			g.Category = types.Category(val)
		}
		break
	}
	return nil
}

func groupFromDoc(doc bson.M) *group {
	var grp group
	if len(doc) != 1 {
		return nil
	}

	for key, val := range doc {
		switch key {
		case "role":
			grp.Role = types.Role(val.(string))
		case "category":
			grp.Category = types.Category(val.(string))
		}
		break
	}

	return &grp
}

// Insert inserts a policy to the persister
func (p *GroupingPersister) Insert(ent types.Entity, grp types.Group) error {
	ss := p.copySession()
	defer ss.closeSession()

	entity := fromEntity(ent)
	group := fromGroup(grp)
	p.log.V(4).Info("insert group policy", "entity", entity, "group", group)

	info, e := ss.UpsertId(entity.String(), bson.M{
		"$addToSet": bson.M{"groups": group},
		"$pull":     bson.M{"deleted": group},
	})
	if e != nil {
		return parseMgoError(e)
	}
	p.log.V(6).Info("upsert to insert", "info", info)
	if info.Updated != 1 && info.UpsertedId == nil {
		if info.Matched == 0 {
			return types.ErrNotFound
		}
		return types.ErrAlreadyExists
	}

	return nil
}

// Remove a policy from the persister
func (p *GroupingPersister) Remove(ent types.Entity, grp types.Group) error {
	ss := p.copySession()
	defer ss.closeSession()

	entity := fromEntity(ent)
	group := fromGroup(grp)
	p.log.V(4).Info("remove group policy", "entity", entity, "group", group)

	e := ss.Update(bson.M{
		"_id":    entity.String(),
		"groups": bson.M{"$elemMatch": group},
	}, bson.M{
		"$pull":     bson.M{"groups": group},
		"$addToSet": bson.M{"deleted": group},
	})
	return parseMgoError(e)
}

// List all policies from the persister
func (p *GroupingPersister) List() ([]types.GroupingPolicy, error) {
	ss := p.copySession()
	defer ss.closeSession()

	iter := ss.Find(nil).Iter()
	defer iter.Close()

	polices := make([]types.GroupingPolicy, 0)

	var gp groups
	for iter.Next(&gp) {
		ent := gp.Entity.asEntity()
		for _, group := range gp.Groups {
			polices = append(polices, types.GroupingPolicy{
				Entity: ent,
				Group:  group.asGroup(),
			})
		}
		gp = groups{}
	}
	if e := iter.Err(); e != nil {
		return nil, e
	}

	p.log.V(4).Info("list grouping policies", "polices", polices)

	return polices, nil
}

type groupingChangeEvent struct {
	OperationType changeStreamOperationType `bson:"operationType,omitempty"`
	FullDocument  groups                    `bson:"fullDocument,omitempty"`
	DocumentKey   struct {
		ID string `bson:"_id,omitempty"`
	} `bson:"documentKey,omitempty"`
	UpdateDescription struct {
		// UpdatedFields map[string]group `bson:"updatedFields,omitempty"`
		UpdatedFields bson.M        `bson:"updatedFields,omitempty"`
		RemovedFields []interface{} `bson:"removedField,omitempty"`
	} `bson:"updateDescription,omitempty"`
}

// Watch any changes occurred about the policies in the persister
func (p *GroupingPersister) Watch(ctx context.Context) (<-chan types.GroupingPolicyChange, error) {
	// test connection
	cs, closer, e := p.connectToWatch(nil)
	if e != nil {
		return nil, e
	}
	firstConnection := true

	changes := make(chan types.GroupingPolicyChange)

	go func() {
		defer close(changes)

		for {
			select {
			case <-ctx.Done():
				return

			default:
				var token *bson.Raw
				if !firstConnection {
					cs, closer, e = p.connectToWatch(token)
					if e != nil {
						p.log.Error(e, "failed to connect")
						time.Sleep(p.retryTimeout)
						continue
					}
				}

				e := p.watch(ctx, cs, changes)
				if e != nil {
					p.log.Error(e, "fetch event change failed, reconnect later")
				}
				token = cs.ResumeToken()
				closer()
				p.log.V(4).Info("change stream closed", "token", token)
				time.Sleep(p.retryTimeout)
			}
		}
	}()

	return changes, nil
}

func (p *GroupingPersister) watch(ctx context.Context, cs *mgo.ChangeStream, changes chan<- types.GroupingPolicyChange) error {
	for {
		var event groupingChangeEvent
		if cs.Next(&event) {
			var change types.GroupingPolicyChange
			p.log.V(6).Info("change event", "id", event.DocumentKey.ID, "event", event)

			entity, e := types.ParseEntity(event.DocumentKey.ID)
			if e != nil {
				p.log.Error(e, "parse entity in change event")
				continue
			}
			change.Entity = entity

			switch event.OperationType {
			case insert:
				change.Method = types.PersistInsert
				if len(event.FullDocument.Groups) > 0 {
					change.Group = event.FullDocument.Groups[0].asGroup()
				}

			case update:
				if fields, ok := event.UpdateDescription.UpdatedFields["groups"]; ok && len(fields.([]interface{})) > 0 {
					docs := fields.([]interface{})
					doc := docs[len(docs)-1]
					change.Method = types.PersistInsert
					change.Group = groupFromDoc(doc.(bson.M)).asGroup()
				} else if fields, ok := event.UpdateDescription.UpdatedFields["deleted"]; ok && len(fields.([]interface{})) > 0 {
					docs := fields.([]interface{})
					doc := docs[len(docs)-1]
					change.Method = types.PersistDelete
					change.Group = groupFromDoc(doc.(bson.M)).asGroup()
				}

			default:
				p.log.Info("unknown event", "operation type", event.OperationType)
				continue
			}

			p.log.V(4).Info("got grouping change event", "change", change)

			select {
			case <-ctx.Done():
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
