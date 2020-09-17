package mgo

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

	ss := c.copySession()
	defer ss.closeSession()

	if e := ss.EnsureIndex(mgo.Index{Key: []string{"entity", "group"}, Unique: true}); e != nil {
		return nil, e
	}

	return c, nil
}

type groupingPolicy struct {
	entity types.Entity
	group  types.Group
}

func (p *groupingPolicy) String() string {
	return fmt.Sprintf("entity: %s, group: %s", p.entity.String(), p.group.String())
}

func (p *groupingPolicy) SetBSON(raw bson.Raw) error {
	m := make(bson.M)
	if e := raw.Unmarshal(&m); e != nil {
		return e
	}

	var ent, grp string
	if v, ok := m["entity"].(string); ok {
		ent = v
	}
	if v, ok := m["group"].(string); ok {
		grp = v
	}

	if ent != "" && grp != "" {
		entity, e := types.ParseEntity(ent)
		if e != nil {
			return nil
		}
		group, e := types.ParseGroup(grp)
		if e != nil {
			return e
		}

		p.entity = entity
		p.group = group
	}

	return nil
}

func parseGroupingPolicyID(id string) (*groupingPolicy, error) {
	parts := strings.SplitN(id, "#", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid grouping policy id: %s", id)
	}

	ent, grp := parts[0], parts[1]
	entity, e := types.ParseEntity(ent)
	if e != nil {
		return nil, nil
	}
	group, e := types.ParseGroup(grp)
	if e != nil {
		return nil, e
	}

	return &groupingPolicy{
		entity: entity,
		group:  group,
	}, nil
}

// Insert inserts a policy to the persister
func (p *GroupingPersister) Insert(ent types.Entity, group types.Group) error {
	ss := p.copySession()
	defer ss.closeSession()

	e := ent.String()
	g := group.String()

	p.log.V(4).Info("insert grouping policy", "entity", e, "group", g)
	return parseMgoError(ss.Insert(bson.M{"_id": e + "#" + g, "entity": e, "group": g}))
}

// Remove a policy from the persister
func (p *GroupingPersister) Remove(ent types.Entity, group types.Group) error {
	ss := p.copySession()
	defer ss.closeSession()

	e := ent.String()
	g := group.String()

	p.log.V(4).Info("remove grouping policy", "entity", e, "group", g)
	return parseMgoError(ss.Remove(bson.M{"entity": e, "group": g}))
}

// List all policies from the persister
func (p *GroupingPersister) List() ([]types.GroupingPolicy, error) {
	ss := p.copySession()
	defer ss.closeSession()

	iter := ss.Find(nil).Iter()
	defer iter.Close()

	polices := make([]types.GroupingPolicy, 0)
	var gp groupingPolicy
	for iter.Next(&gp) {
		polices = append(polices, types.GroupingPolicy{Entity: gp.entity, Group: gp.group})
		gp = groupingPolicy{}
	}
	if e := iter.Err(); e != nil {
		return nil, e
	}

	p.log.V(4).Info("list grouping policies", "count", len(polices))
	p.log.V(5).Info("list grouping policies", "polices", polices)

	return polices, nil
}

type groupingChangeEvent struct {
	OperationType changeStreamOperationType `bson:"operationType,omitempty"`
	FullDocument  groupingPolicy            `bson:"fullDocument,omitempty"`
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
					// and event be deleted already
					if event.FullDocument.entity == nil || event.FullDocument.group == nil {
						policy, e := parseGroupingPolicyID(event.DocumentKey.ID)
						if e != nil {
							p.log.Error(e, "parse document key in permission delete event", "id", event.DocumentKey.ID)
							continue
						}
						event.FullDocument = *policy
					}

				case delete:
					method = types.PersistDelete
					// we cannot get fulldocument if deleted, and have to parse it from id
					policy, e := parseGroupingPolicyID(event.DocumentKey.ID)
					if e != nil {
						p.log.Error(e, "parse document key in grouping delete event", "id ", event.DocumentKey.ID)
						continue
					}
					event.FullDocument = *policy

				default:
					p.log.Info("unknown operation type", "operation type", event.OperationType, "document", event.FullDocument.String())
					continue
				}

				p.log.V(4).Info("got grouping change event", "method", method, "document", event.FullDocument.String())
				change := types.GroupingPolicyChange{
					GroupingPolicy: types.GroupingPolicy{
						Entity: event.FullDocument.entity,
						Group:  event.FullDocument.group,
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
					p.log.Info("watch found nothing, retry later")
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
