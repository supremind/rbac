package mgo

import (
	"context"
	"errors"
	"time"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/go-logr/logr"
	"github.com/houz42/rbac/types"
)

// GroupingPersister is a GroupingPersister backed by mongodb
type GroupingPersister struct {
	*collection
	log logr.Logger
}

// NewGrouping uses the given mongodb collection as backend to persist grouping polices
func NewGrouping(coll *mgo.Collection) (*GroupingPersister, error) {
	c := &GroupingPersister{
		collection: &collection{Collection: coll},
		log
	}
	ss := c.copySession()
	defer ss.closeSession()

	if e := ss.EnsureIndex(mgo.Index{Key: []string{"entity", "grouping"}, Unique: true}); e != nil {
		return nil, e
	}

	return c, nil
}

type groupingPolicy struct {
	entity types.Entity
	group  types.Group
}

type groupingPolicyDO struct {
	Entity string
	Group  string
}

func (p *groupingPolicy) GetBSON() (interface{}, error) {
	return groupingPolicyDO{Entity: p.entity.String(), Group: p.group.String()}, nil
}

func (p *groupingPolicy) SetBSON(raw bson.Raw) error {
	do := groupingPolicyDO{}
	if e := raw.Unmarshal(&do); e != nil {
		return e
	}

	ent, e := types.ParseEntity(do.Entity)
	if e != nil {
		return e
	}
	group, e := types.ParseGroup(do.Group)
	if e != nil {
		return e
	}

	p.entity = ent
	p.group = group
	return nil
}

// Insert inserts a policy to the persister
func (p *GroupingPersister) Insert(ent types.Entity, group types.Group) error {
	ss := p.copySession()
	defer ss.closeSession()

	return ss.Insert(groupingPolicy{entity: ent, group: group})
}

// Remove a policy from the persister
func (p *GroupingPersister) Remove(ent types.Entity, group types.Group) error {
	ss := p.copySession()
	defer ss.closeSession()

	return ss.Remove(groupingPolicy{entity: ent, group: group})
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

	return polices, nil
}

type groupingChangeEvent struct {
	OperationType changeStreamOperationType
	FullDocument  groupingPolicy
}

// Watch any changes occurred about the policies in the persister
func (p *GroupingPersister) Watch(ctx context.Context) (<-chan types.GroupingPolicyChange, error) {
	changes := make(chan types.GroupingPolicyChange)

	run := func() error {
		ss := p.copySession()
		defer ss.closeSession()

		cs, e := ss.Watch(nil, mgo.ChangeStreamOptions{
			FullDocument: mgo.UpdateLookup,
		})
		if e != nil {
			return e
		}
		defer cs.Close()

		var event groupingChangeEvent
		var change types.GroupingPolicyChange
	fetchNext:
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()

			default:
				if cs.Next(&event) {
					switch event.OperationType {
					case insert:
						change.Method = types.PersistInsert
					case delete:
						change.Method = types.PersistDelete
					case update, replace:
						change.Method = types.PersistUpdate
					default:
						p.log.Info("unknown operation type", "operation type", event.OperationType, "document", event.FullDocument)
						continue
					}

					change.Entity = event.FullDocument.entity
					change.Group = event.FullDocument.group
					changes <- change

				} else if e := cs.Err(); e != nil {
					if errors.Is(e, mgo.ErrNotFound) {
						p.log.Info("watch found nothing, retry later")
						time.Sleep(10 * time.Second)
						goto fetchNext
					}
					return e
				}
			}
		}
	}

	go func() {
		for {
			e := run()
			select {
			case <-ctx.Done():
				return
			default:
				p.log.Error(e, "watch failed, retry")
			}
		}
	}()

	return changes, nil
}
