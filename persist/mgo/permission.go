package mgo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/houz42/rbac/types"
	"github.com/supremind/pkg/stream"
)

// PermissionPersister is a PermissionPersister backed by mongodb
type PermissionPersister struct {
	*collection
}

// NewPermission uses the given mongodb collection as backend to persist grouping polices
func NewPermission(coll *mgo.Collection, opts ...collectionOption) (*PermissionPersister, error) {
	c := &PermissionPersister{&collection{Collection: coll}}
	for _, opt := range opts {
		opt(c.collection)
	}

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

func (p permissionPolicy) String() string {
	var s, o, a string
	if p.subject != nil {
		s = p.subject.String()
	} else {
		s = "nil"
	}
	if p.object != nil {
		s = p.object.String()
	} else {
		o = "nil"
	}
	a = p.action.String()

	return fmt.Sprintf("subject: %s, object: %s, action: %s", s, o, a)
}

func (p *permissionPolicy) SetBSON(raw bson.Raw) error {
	m := make(bson.M)
	if e := raw.Unmarshal(&m); e != nil {
		return e
	}

	var sub, obj, act string
	if v, ok := m["subject"].(string); ok {
		sub = v
	}
	if v, ok := m["object"].(string); ok {
		obj = v
	}
	if v, ok := m["action"].(string); ok {
		act = v
	}

	if sub != "" && obj != "" && act != "" {
		subject, e := types.ParseSubject(sub)
		if e != nil {
			return e
		}
		object, e := types.ParseObject(obj)
		if e != nil {
			return e
		}
		action, e := types.ParseAction(act)
		if e != nil {
			return e
		}

		p.subject = subject
		p.object = object
		p.action = action
	}

	return nil
}

func parsePermissionPolicyID(id string) (*permissionPolicy, error) {
	parts := strings.SplitN(id, "#", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid permission policy id: %s", id)
	}

	sub, obj := parts[0], parts[1]
	subject, e := types.ParseSubject(sub)
	if e != nil {
		return nil, nil
	}
	object, e := types.ParseObject(obj)
	if e != nil {
		return nil, e
	}

	return &permissionPolicy{
		subject: subject,
		object:  object,
	}, nil
}

// Insert a permission policy to the persister
func (p *PermissionPersister) Insert(sub types.Subject, obj types.Object, act types.Action) error {
	ss := p.copySession()
	defer ss.closeSession()

	s := sub.String()
	o := obj.String()

	p.log.V(4).Info("insert permission policy", "subject", s, "object", o, "action", act.String())
	return ss.Insert(bson.M{"_id": s + "#" + o, "subject": s, "object": o, "action": act.String()})
}

// Update a permission policy to the persister
func (p *PermissionPersister) Update(sub types.Subject, obj types.Object, act types.Action) error {
	ss := p.copySession()
	defer ss.closeSession()

	s := sub.String()
	o := obj.String()

	p.log.V(4).Info("update permission policy", "subject", s, "object", o, "action", act.String())
	return ss.Update(bson.M{"subject": s, "object": o}, bson.M{"$set": bson.M{"action": act.String()}})
}

// Remove a permission policy from the persister
func (p *PermissionPersister) Remove(sub types.Subject, obj types.Object) error {
	ss := p.copySession()
	defer ss.closeSession()

	s := sub.String()
	o := obj.String()

	p.log.V(4).Info("remove permission policy", "subject", s, "object", o)
	return ss.Remove(bson.M{"subject": s, "object": o})
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

	p.log.V(4).Info("list permission policies", "count", len(polices))
	p.log.V(5).Info("list permission policies", "polices", polices)

	return polices, nil
}

type permissionChangeEvent struct {
	OperationType changeStreamOperationType `bson:"operationType,omitempty"`
	FullDocument  permissionPolicy          `bson:"fullDocument,omitempty"`
	DocumentKey   struct {
		ID string `bson:"_id,omitempty"`
	} `bson:"documentKey,omitempty"`
	UpdateDescription struct {
		UpdatedFields map[string]string `bson:"updatedFields,omitempty"`
	} `bson:"updateDescription,omitempty"`
}

// Watch any changes occurred about the polices in the persister
func (p *PermissionPersister) Watch(ctx context.Context) (<-chan types.PermissionPolicyChange, error) {
	connect := func() (*mgo.ChangeStream, io.Closer, error) {
		ss := p.copySession()
		cs, e := ss.Watch(nil, mgo.ChangeStreamOptions{
			FullDocument: mgo.UpdateLookup,
		})
		if e != nil {
			return nil, nil, e
		}

		p.log.Info("watch mongo stream change")

		return cs, stream.FuncCloser(func() error {
			cs.Close()
			ss.closeSession()
			return nil
		}), nil
	}

	fetch := func(cs *mgo.ChangeStream, changes chan<- types.PermissionPolicyChange) error {
		for {
			var event permissionChangeEvent
			if cs.Next(&event) {
				var method types.PersistMethod

				switch event.OperationType {
				case insert:
					method = types.PersistInsert
				case update:
					method = types.PersistUpdate
					// returned fulldocument is queried after updating, may not be the same as which intended to update to
					// and event be deleted already
					if event.FullDocument.subject == nil || event.FullDocument.object == nil {
						policy, e := parsePermissionPolicyID(event.DocumentKey.ID)
						if e != nil {
							p.log.Error(e, "parse document key in permission delete event", "id", event.DocumentKey.ID)
							continue
						}
						event.FullDocument = *policy
					}
					action, e := types.ParseAction(event.UpdateDescription.UpdatedFields["action"])
					if e != nil {
						p.log.Error(e, "parse action in update description", "id", event.DocumentKey.ID, "update description", event.UpdateDescription)
						continue
					}
					event.FullDocument.action = action

				case delete:
					method = types.PersistDelete
					// we cannot get fulldocument if deleted, and have to parse it from id
					policy, e := parsePermissionPolicyID(event.DocumentKey.ID)
					if e != nil {
						p.log.Error(e, "parse document key in permission delete event", "id ", event.DocumentKey.ID)
						continue
					}
					event.FullDocument = *policy

				default:
					p.log.Info("unknown operation type", "operation type", event.OperationType, "document", event.FullDocument.String())
					continue
				}

				p.log.V(4).Info("got permission change event", "method", method, "document", event.FullDocument.String(), "key", event.DocumentKey.ID)
				change := types.PermissionPolicyChange{
					PermissionPolicy: types.PermissionPolicy{
						Subject: event.FullDocument.subject,
						Object:  event.FullDocument.object,
						Action:  event.FullDocument.action,
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
					time.Sleep(10 * time.Second)
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

	changes := make(chan types.PermissionPolicyChange)
	go func() {
		for {
			select {
			case <-ctx.Done():
				closer.Close()
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
				closer.Close()
				if e != nil {
					p.log.Error(e, "fetch event change failed, reconnect later")
				}
				time.Sleep(p.retryTimeout)
			}
		}
	}()

	return changes, nil
}
