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

// PermissionPersister is a PermissionPersister backed by mongodb
type PermissionPersister struct {
	*collection
	log logr.Logger
}

// NewPermission uses the given mongodb collection as backend to persist grouping polices
func NewPermission(coll *mgo.Collection) (*PermissionPersister, error) {
	c := &PermissionPersister{&collection{Collection: coll}}
	ss := c.copySession()
	defer ss.closeSession()

	if e := ss.EnsureIndex(mgo.Index{Key: []string{"subject", "object"}, Unique: true}); e != nil {
		return nil, e
	}

	return c, nil
}

type permissionPolicy struct {
	subject types.Subject
	object  types.Object
	action  types.Action
}

type permissionPolicyDO struct {
	Subject string
	Object  string
	Action  types.Action
}

func (p *permissionPolicy) GetBSON() (interface{}, error) {
	return permissionPolicyDO{
		Subject: p.subject.String(),
		Object:  p.object.String(),
		Action:  p.action,
	}, nil
}

func (p *permissionPolicy) SetBSON(raw bson.Raw) error {
	do := permissionPolicyDO{}
	if e := raw.Unmarshal(&do); e != nil {
		return e
	}

	sub, e := types.ParseSubject(do.Subject)
	if e != nil {
		return e
	}
	obj, e := types.ParseObject(do.Object)
	if e != nil {
		return e
	}

	p.subject = sub
	p.object = obj
	p.action = do.Action
	return nil
}

// Upsert insert or update a permission policy to the persister
func (p *PermissionPersister) Upsert(sub types.Subject, obj types.Object, act types.Action) error {
	ss := p.copySession()
	defer ss.closeSession()

	return ss.UpdateOne(bson.M{"subject": sub.String(), "object": obj.String()},
		permissionPolicy{subject: sub, object: obj, action: act},
		bson.M{"upsert": true},
	)
}

// Remove a permission policy from the persister
func (p *PermissionPersister) Remove(sub types.Subject, obj types.Object) error {
	ss := p.copySession()
	defer ss.closeSession()

	return ss.Remove(bson.M{"subject": sub.String(), "object": obj.String()})
}

// List all polices from the persister
func (p *PermissionPersister) List() ([]types.PermissionPolicy, error) {
	ss := p.copySession()
	defer ss.closeSession()

	iter := ss.Find(nil).Iter()
	defer iter.Close()

	polices := make([]types.PermissionPolicy, 0)
	var mp permissionPolicy
	for iter.Next(&mp) {
		polices = append(polices, types.PermissionPolicy{Subject: mp.subject, Object: mp.object, Action: mp.action})
		mp = permissionPolicy{}
	}
	if e := iter.Err(); e != nil {
		return nil, e
	}

	return polices, nil
}

type permissionChangeEvent struct {
	OperationType changeStreamOperationType
	FullDocument  permissionPolicy
}

// Watch any changes occurred about the polices in the persister
func (p *PermissionPersister) Watch(ctx context.Context) (<-chan types.PermissionPolicyChange, error) {
	changes := make(chan types.PermissionPolicyChange)

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

		var event permissionChangeEvent
		var change types.PermissionPolicyChange
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

					change.Subject = event.FullDocument.subject
					change.Object = event.FullDocument.object
					change.Action = event.FullDocument.action
					changes <- change

				} else {
					if e := cs.Err(); e != nil {
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
	}

	go func() {
		for {
			e := run()
			_ = e
			// todo: log or panic
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
