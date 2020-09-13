package mgo

import "github.com/globalsign/mgo"

type collection struct {
	*mgo.Collection
}

func (c *collection) copySession() *collection {
	db := c.Database
	return &collection{db.Session.Copy().DB(db.Name).C(c.Name)}
}

func (c *collection) closeSession() {
	c.Database.Session.Close()
}

type changeStreamOperationType string

const (
	insert  changeStreamOperationType = "insert"
	delete  changeStreamOperationType = "delete"
	update  changeStreamOperationType = "update"
	replace changeStreamOperationType = "replace"
)
