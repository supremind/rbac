package mgo_test

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/globalsign/mgo"
	"github.com/go-logr/stdr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/houz42/rbac/persist/mgo"
	. "github.com/houz42/rbac/persist/test"
)

func TestPersisters(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "mgo persisters")
}

var (
	db *mgo.Database
)

var _ = BeforeSuite(func() {
	const dbName = "test-db"
	const testDB = "mongodb://localhost:27017/test-db"
	ss, e := mgo.Dial(testDB)
	Expect(e).To(Succeed())
	db = ss.DB(dbName)

	logger := stdr.New(log.New(os.Stderr, "", log.LstdFlags|log.Lshortfile))
	stdr.SetVerbosity(4)

	gp, e := NewGrouping(db.C("grouping"), WithLogger(logger), SetRetryTimeout(1*time.Second))
	Expect(e).To(Succeed())
	TestGroupingPersister(gp)

	pp, e := NewPermission(db.C("permission"), WithLogger(logger), SetRetryTimeout(100*time.Microsecond))
	Expect(e).To(Succeed())
	TestPermissionPersister(pp)
})

var _ = AfterSuite(func() {
	db.C("grouping").RemoveAll(nil)
	db.C("permission").RemoveAll(nil)
})

var _ = GroupingCases
var _ = PermissionCases
