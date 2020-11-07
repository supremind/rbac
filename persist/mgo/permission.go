package mgo

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/supremind/rbac/types"
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

	return c, nil
}

type permissions struct {
	Subject     subject      `bson:"_id"`
	Permissions []permission `bson:"permissions"`
	Deleted     []object     `bson:"deleted"`
}

type permission struct {
	Object object       `bson:"object"`
	Action types.Action `bson:"action"`
}

func objectFromDoc(doc bson.M) *object {
	var obj object
	if len(doc) != 1 {
		return nil
	}

	for key, val := range doc {
		switch key {
		case "article":
			obj.Article = types.Article(val.(string))
		case "category":
			obj.Category = types.Category(val.(string))
		}
		break
	}

	return &obj

}

func actionFromDoc(doc interface{}) types.Action {
	val, ok := doc.(int)
	if !ok {
		return 0
	}
	return types.Action(val)
}

type subject struct {
	User types.User `bson:"user,omitempty"`
	Role types.Role `bson:"role,omitempty"`
}

func (s *subject) String() string {
	switch {
	case s.User != "":
		return s.User.String()
	case s.Role != "":
		return s.Role.String()
	}
	return ""
}

func fromSubject(sub types.Subject) subject {
	s := subject{}
	switch sub.(type) {
	case types.User:
		s.User = sub.(types.User)
	case types.Role:
		s.Role = sub.(types.Role)
	}
	return s
}

func (s *subject) asSubject() types.Subject {
	var sub types.Subject
	switch {
	case s.User != "":
		sub = s.User
	case s.Role != "":
		sub = s.Role
	}
	return sub
}

func (s *subject) SetBSON(raw bson.Raw) error {
	var str string
	if e := raw.Unmarshal(&str); e != nil {
		return e
	}

	sub, err := types.ParseSubject(str)
	if err != nil {
		return err
	}

	*s = fromSubject(sub)
	return nil
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

func fromObject(obj types.Object) object {
	o := object{}
	switch obj.(type) {
	case types.Article:
		o.Article = obj.(types.Article)
	case types.Category:
		o.Category = obj.(types.Category)
	}
	return o
}

func (obj *object) asObject() types.Object {
	var o types.Object
	switch {
	case obj.Article != "":
		o = obj.Article
	case obj.Category != "":
		o = obj.Category
	}
	return o
}

// Insert a permission policy to the persister
func (p *PermissionPersister) Insert(sub types.Subject, obj types.Object, act types.Action) error {
	ss := p.copySession()
	defer ss.closeSession()

	subject := fromSubject(sub)
	object := fromObject(obj)
	perm := permission{Object: object, Action: act}
	p.log.V(4).Info("insert permission policy", "subject", subject, "object", object, "action", act)

	info, e := ss.Upsert(bson.M{
		"_id":                subject.String(),
		"permissions.object": bson.M{"$ne": object},
	}, bson.M{
		"$addToSet": bson.M{"permissions": perm},
		"$pull":     bson.M{"deleted": object},
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

// Update a permission policy to the persister
func (p *PermissionPersister) Update(sub types.Subject, obj types.Object, act types.Action) error {
	ss := p.copySession()
	defer ss.closeSession()

	subject := fromSubject(sub)
	object := fromObject(obj)
	p.log.V(4).Info("update permission policy", "subject", subject, "object", object, "action", act)

	e := ss.Update(bson.M{
		"_id":         subject.String(),
		"permissions": bson.M{"$elemMatch": bson.M{"object": object}},
	}, bson.M{
		"$set": bson.M{"permissions.$.action": act},
	})

	return parseMgoError(e)
}

// Remove a permission policy from the persister
func (p *PermissionPersister) Remove(sub types.Subject, obj types.Object) error {
	ss := p.copySession()
	defer ss.closeSession()

	subject := fromSubject(sub)
	object := fromObject(obj)
	p.log.V(4).Info("remove permission policy", "subject", subject, "object", object)

	e := ss.Update(bson.M{
		"_id":         subject.String(),
		"permissions": bson.M{"$elemMatch": bson.M{"object": object}},
	}, bson.M{
		"$pull":     bson.M{"permissions": bson.M{"object": object}},
		"$addToSet": bson.M{"deleted": object},
	})
	return parseMgoError(e)
}

// List all polices from the persister
func (p *PermissionPersister) List() ([]types.PermissionPolicy, error) {
	ss := p.copySession()
	defer ss.closeSession()

	iter := ss.Find(nil).Iter()
	defer iter.Close()

	polices := make([]types.PermissionPolicy, 0)
	var mp permissions
	for iter.Next(&mp) {
		sub := mp.Subject.asSubject()
		for _, perm := range mp.Permissions {
			polices = append(polices, types.PermissionPolicy{
				Subject: sub,
				Object:  perm.Object.asObject(),
				Action:  perm.Action,
			})
		}
		mp = permissions{}
	}
	if e := iter.Err(); e != nil {
		return nil, e
	}

	p.log.V(4).Info("list permission policies", "polices", polices)

	return polices, nil
}

type permissionChangeEvent struct {
	OperationType changeStreamOperationType `bson:"operationType,omitempty"`
	FullDocument  permissions               `bson:"fullDocument,omitempty"`
	DocumentKey   struct {
		ID string `bson:"_id,omitempty"`
	} `bson:"documentKey,omitempty"`
	UpdateDescription struct {
		UpdatedFields bson.M        `bson:"updatedFields,omitempty"`
		RemovedFields []interface{} `bson:"removedFields,omitempty"`
	} `bson:"updateDescription,omitempty"`
}

// Watch any changes occurred about the polices in the persister
func (p *PermissionPersister) Watch(ctx context.Context) (<-chan types.PermissionPolicyChange, error) {
	cs, closer, e := p.connectToWatch(nil)
	if e != nil {
		return nil, e
	}
	firstConnection := true

	changes := make(chan types.PermissionPolicyChange)

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
				p.log.V(2).Info("change stream closed", "token", token)
				time.Sleep(p.retryTimeout)
			}
		}
	}()

	return changes, nil
}

func (p *PermissionPersister) watch(ctx context.Context, cs *mgo.ChangeStream, changes chan<- types.PermissionPolicyChange) error {
	for {
		var event permissionChangeEvent
		if cs.Next(&event) {
			var change types.PermissionPolicyChange
			p.log.V(6).Info("change event", "event", event)

			sub, e := types.ParseSubject(event.DocumentKey.ID)
			if e != nil {
				p.log.Error(e, "parse subjct in change event")
				continue
			}
			change.Subject = sub

			switch event.OperationType {
			case insert:
				change.Method = types.PersistInsert
				if len(event.FullDocument.Permissions) > 0 {
					change.Object = event.FullDocument.Permissions[0].Object.asObject()
					change.Action = event.FullDocument.Permissions[0].Action
				}

			case update, replace:
				if fields, ok := event.UpdateDescription.UpdatedFields["permissions"]; ok && len(fields.([]interface{})) > 0 {
					docs := fields.([]interface{})
					doc := docs[len(docs)-1].(bson.M)
					change.Method = types.PersistInsert
					change.Action = actionFromDoc(doc["action"])
					change.Object = objectFromDoc(doc["object"].(bson.M)).asObject()
				} else if fields, ok := event.UpdateDescription.UpdatedFields["deleted"]; ok && len(fields.([]interface{})) > 0 {
					docs := fields.([]interface{})
					doc := docs[len(docs)-1].(bson.M)
					change.Method = types.PersistDelete
					change.Object = objectFromDoc(doc).asObject()
				} else if doc := event.UpdateDescription.UpdatedFields; len(doc) == 1 {
					for key, val := range doc {
						if strings.HasPrefix(key, "permissions.") {
							index := strings.TrimSuffix(strings.TrimPrefix(key, "permissions."), ".action")
							idx, e := strconv.Atoi(index)
							if e != nil {
								p.log.Error(e, "parse updated permission id", "doc", doc)
								continue
							}
							if idx >= len(event.FullDocument.Permissions) {
								// fixme: how to get correct permission updates?
								// https://docs.mongodb.com/manual/changeStreams/#lookup-full-document-for-update-operations
								p.log.V(2).Info("incorrect permission id in storage, content may be changed after updating")
								continue
							}
							change.Object = event.FullDocument.Permissions[idx].Object.asObject()
							change.Action = actionFromDoc(val)
							change.Method = types.PersistUpdate
						}
						break
					}
				} else {
					continue
				}

			default:
				p.log.Info("unknown event", "operation type")
				continue
			}

			p.log.V(4).Info("got permission change", "change", change)

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
