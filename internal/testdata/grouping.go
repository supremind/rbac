package testdata

import (
	"strconv"

	. "github.com/houz42/rbac/types"
)

func init() {
	loadUsersAndRoles()
}

var (
	UserRoles map[User][]Role
	RoleUsers map[Role][]User
)

func loadUsersAndRoles() {
	UserRoles = make(map[User][]Role)
	RoleUsers = make(map[Role][]User)
	for i := 0; i < 10; i++ {
		user := User(strconv.Itoa(i))
		role2 := Role("2_" + strconv.Itoa(i%2))
		role3 := Role("3_" + strconv.Itoa(i%3))
		role5 := Role("5_" + strconv.Itoa(i%5))

		UserRoles[user] = []Role{role2, role3, role5}
		RoleUsers[role2] = append(RoleUsers[role2], user)
		RoleUsers[role3] = append(RoleUsers[role3], user)
		RoleUsers[role5] = append(RoleUsers[role5], user)
	}
}

var ObjectGroupings = []struct {
	Art Article
	Cat Category
}{
	{Art: Article("project apollo"), Cat: Category("peace")},
	{Art: Article("manhattan project"), Cat: Category("war")},
	{Art: Article("operation market garden"), Cat: Category("war")},
	{Art: Article("operation overlord"), Cat: Category("war")},

	{Art: Article("project apollo"), Cat: Category("america")},
	{Art: Article("manhattan project"), Cat: Category("america")},
	{Art: Article("operation market garden"), Cat: Category("europe")},
	{Art: Article("operation overlord"), Cat: Category("europe")},

	{Art: Article("project apollo"), Cat: Category("success")},
	{Art: Article("manhattan project"), Cat: Category("success")},
	{Art: Article("operation market garden"), Cat: Category("success")},
	{Art: Article("operation overlord"), Cat: Category("fail")},
}

var UserToArticlePolices = []struct {
	Sub User
	Obj Article
	Act Action
}{}

var UserToCategoryPolices = []struct {
	Sub User
	Obj Category
	Act Action
}{
	{Sub: User("0"), Obj: Category("war"), Act: Read},
	{Sub: User("0"), Obj: Category("peace"), Act: ReadWrite},
	{Sub: User("0"), Obj: Category("fail"), Act: Read},
	{Sub: User("1"), Obj: Category("europe"), Act: ReadExec},
	{Sub: User("2"), Obj: Category("fail"), Act: ReadWrite},
	{Sub: User("3"), Obj: Category("war"), Act: ReadExec},
}

var RoleToArticlePolices = []struct {
	Sub Role
	Obj Article
	Act Action
}{
	{Sub: Role("2_0"), Obj: Article("project apollo"), Act: Read},
	{Sub: Role("2_1"), Obj: Article("project apollo"), Act: ReadWriteExec},
	{Sub: Role("3_0"), Obj: Article("manhattan project"), Act: Read},
	{Sub: Role("3_1"), Obj: Article("manhattan project"), Act: ReadWrite},
	{Sub: Role("3_2"), Obj: Article("manhattan project"), Act: ReadExec},
}

var RoleToCategoryPolices = []struct {
	Sub Role
	Obj Category
	Act Action
}{
	{Sub: Role("2_0"), Obj: Category("europe"), Act: Read},
	{Sub: Role("2_1"), Obj: Category("europe"), Act: ReadWriteExec},
	{Sub: Role("3_0"), Obj: Category("war"), Act: Read},
	{Sub: Role("3_1"), Obj: Category("war"), Act: ReadWrite},
	{Sub: Role("3_2"), Obj: Category("war"), Act: ReadExec},
}
