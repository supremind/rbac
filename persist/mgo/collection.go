package mgo

import (
	"errors"
	"time"

	"github.com/globalsign/mgo"
	"github.com/go-logr/logr"
	"github.com/houz42/rbac/types"
)

// common collection utilities
type collection struct {
	*mgo.Collection
	log          logr.Logger
	retryTimeout time.Duration
}

func (c *collection) copySession() *collection {
	db := c.Database
	return &collection{Collection: db.Session.Copy().DB(db.Name).C(c.Name)}
}

func (c *collection) closeSession() {
	c.Database.Session.Close()
}

type collectionOption func(*collection)

// WithLogger set a logger for the collection to use with
func WithLogger(log logr.Logger) collectionOption {
	return func(coll *collection) {
		coll.log = log
	}
}

// SetRetryTimeout controls how long it will wait before retry watch change stream
func SetRetryTimeout(d time.Duration) collectionOption {
	return func(coll *collection) {
		coll.retryTimeout = d
	}
}

type changeStreamOperationType string

const (
	insert  changeStreamOperationType = "insert"
	delete  changeStreamOperationType = "delete"
	update  changeStreamOperationType = "update"
	replace changeStreamOperationType = "replace"
)

func parseMgoError(e error) error {
	if e == nil {
		return nil
	}

	switch {
	case errors.Is(e, mgo.ErrNotFound):
		return types.ErrNotFound
	case mgo.IsDup(e):
		return types.ErrAlreadyExists
	}

	return e
}
