package mgo

import (
	"time"

	"github.com/globalsign/mgo"
	"github.com/go-logr/logr"
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
