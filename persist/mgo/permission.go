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

type permissionPolicyDO struct {
	ID      string       `bson:"_id"`
	Subject subject      `bson:"subject,omitempty"`
	Object  object       `bson:"object,omitempty"`
	Action  types.Action `bson:"action,omitempty"`
}

func newPermissionPolicyDO(sub types.Subject, obj types.Object, act types.Action) *permissionPolicyDO {
	p := &permissionPolicyDO{Action: act}

	switch sub.(type) {
	case types.User:
		p.Subject.User = sub.(types.User)
	case types.Role:
		p.Subject.Role = sub.(types.Role)
	}

	switch obj.(type) {
	case types.Article:
		p.Object.Article = obj.(types.Article)
	case types.Category:
		p.Object.Category = obj.(types.Category)
	}

	p.ID = p.id()
	return p
}

func (p *permissionPolicyDO) id() string {
	return p.Subject.String() + "#" + p.Object.String()
}

func (p *permissionPolicyDO) parseID(id string) error {
	parts := strings.SplitN(id, "#", 2)
	if len(parts) < 2 {
		return fmt.Errorf("invalid grouping policy id: %s", id)
	}

	subject, object := parts[0], parts[1]
	sub, e := types.ParseSubject(subject)
	if e != nil {
		return nil
	}
	switch sub.(type) {
	case types.User:
		p.Subject.User = sub.(types.User)
	case types.Role:
		p.Subject.Role = sub.(types.Role)
	}

	obj, e := types.ParseObject(object)
	if e != nil {
		return e
	}
	switch obj.(type) {
	case types.Article:
		p.Object.Article = obj.(types.Article)
	case types.Category:
		p.Object.Category = obj.(types.Category)
	}

	return nil
}

func (p *permissionPolicyDO) asPermissionPolicy() types.PermissionPolicy {
	pp := types.PermissionPolicy{Action: p.Action}

	switch {
	case p.Subject.User != "":
		pp.Subject = p.Subject.User
	case p.Subject.Role != "":
		pp.Subject = p.Subject.Role
	}

	switch {
	case p.Object.Article != "":
		pp.Object = p.Object.Article
	case p.Object.Category != "":
		pp.Object = p.Object.Category
	}

	return pp
}

type subject struct {
	User types.User `bson:"user,omitempty"`
	Role types.Role `bson:"role,omitempty"`
}

func (sub *subject) String() string {
	switch {
	case sub.User != "":
		return sub.User.String()
	case sub.Role != "":
		return sub.Role.String()
	}
	return ""
}

type object struct {
	Article  types.Article  `bson:"article,omitempty"`
	Category types.Category `bson:"category,omitempty"`
}

func (obj *object) String() string {
	switch {
	case obj.Article != "":
		return obj.Article.String()
	case obj.Category != "":
		return obj.Category.String()
	}
	return ""
}

// Insert a permission policy to the persister
func (p *PermissionPersister) Insert(sub types.Subject, obj types.Object, act types.Action) error {
	ss := p.copySession()
	defer ss.closeSession()

	policy := newPermissionPolicyDO(sub, obj, act)
	p.log.V(4).Info("insert permission policy", "policy", policy)

	return parseMgoError(ss.Insert(policy))
}

// Update a permission policy to the persister
func (p *PermissionPersister) Update(sub types.Subject, obj types.Object, act types.Action) error {
	ss := p.copySession()
	defer ss.closeSession()

	policy := newPermissionPolicyDO(sub, obj, act)
	p.log.V(4).Info("update permission policy", "policy", policy)

	return parseMgoError(ss.UpdateId(policy.ID, bson.M{"$set": bson.M{"action": act}}))
}

// Remove a permission policy from the persister
func (p *PermissionPersister) Remove(sub types.Subject, obj types.Object) error {
	ss := p.copySession()
	defer ss.closeSession()

	policy := newPermissionPolicyDO(sub, obj, 0)
	p.log.V(4).Info("remove permission policy", "policy", policy)

	return parseMgoError(ss.RemoveId(policy.ID))
}

// List all polices from the persister
func (p *PermissionPersister) List() ([]types.PermissionPolicy, error) {
	ss := p.copySession()
	defer ss.closeSession()

	iter := ss.Find(nil).Iter()
	defer iter.Close()

	polices := make([]types.PermissionPolicy, 0)
	var mp permissionPolicyDO
	for iter.Next(&mp) {
		polices = append(polices, mp.asPermissionPolicy())
		mp = permissionPolicyDO{}
	}
	if e := iter.Err(); e != nil {
		return nil, e
	}

	p.log.V(4).Info("list permission policies", "polices", polices)

	return polices, nil
}

type permissionChangeEvent struct {
	OperationType changeStreamOperationType `bson:"operationType,omitempty"`
	FullDocument  permissionPolicyDO        `bson:"fullDocument,omitempty"`
	DocumentKey   struct {
		ID string `bson:"_id,omitempty"`
	} `bson:"documentKey,omitempty"`
	UpdateDescription struct {
		UpdatedFields bson.M `bson:"updatedFields,omitempty"`
	} `bson:"updateDescription,omitempty"`
}

// Watch any changes occurred about the polices in the persister
func (p *PermissionPersister) Watch(ctx context.Context) (<-chan types.PermissionPolicyChange, error) {
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

	fetch := func(cs *mgo.ChangeStream, changes chan<- types.PermissionPolicyChange) error {
		for {
			var event permissionChangeEvent
			if cs.Next(&event) {
				var method types.PersistMethod

				switch event.OperationType {
				case insert:
					method = types.PersistInsert

				case update, replace:
					method = types.PersistUpdate
					// returned fulldocument is queried after updating, may not be the same as which intended to update to
					// and event be deleted already
					policy := permissionPolicyDO{}
					if e := policy.parseID(event.DocumentKey.ID); e != nil {
						p.log.Error(e, "parse permission policy id", "id", event.DocumentKey.ID)
						continue
					}
					if v, ok := event.UpdateDescription.UpdatedFields["action"].(int); !ok {
						p.log.Info("parse action in update description", "id", event.DocumentKey.ID, "update description", event.UpdateDescription)
						continue
					} else {
						policy.Action = types.Action(v)
					}

					event.FullDocument = policy

				case delete:
					method = types.PersistDelete
					// we cannot get fulldocument if deleted, and have to parse it from id
					policy := permissionPolicyDO{}
					if e := policy.parseID(event.DocumentKey.ID); e != nil {
						p.log.Error(e, "parse permission policy id", "id", event.DocumentKey.ID)
						continue
					}
					event.FullDocument = policy

				default:
					p.log.Info("unknown operation type", "operation type", event.OperationType, "document", event.FullDocument)
					continue
				}

				p.log.V(4).Info("got permission change event", "method", method, "document", event.FullDocument, "key", event.DocumentKey.ID)
				policy := event.FullDocument.asPermissionPolicy()
				change := types.PermissionPolicyChange{
					PermissionPolicy: types.PermissionPolicy{
						Subject: policy.Subject,
						Object:  policy.Object,
						Action:  policy.Action,
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

	changes := make(chan types.PermissionPolicyChange)
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
