package testdata

import (
	"strconv"

	"github.com/houz42/rbac/types"
)

func init() {
	loadUsersAndRoles()
}

var (
	UserRoles map[types.User][]types.Role
	RoleUsers map[types.Role][]types.User
)

func loadUsersAndRoles() {
	UserRoles = make(map[types.User][]types.Role)
	RoleUsers = make(map[types.Role][]types.User)
	for i := 0; i < 10; i++ {
		user := types.User(strconv.Itoa(i))
		role2 := types.Role("2_" + strconv.Itoa(i%2))
		role3 := types.Role("3_" + strconv.Itoa(i%3))
		role5 := types.Role("5_" + strconv.Itoa(i%5))

		UserRoles[user] = []types.Role{role2, role3, role5}
		RoleUsers[role2] = append(RoleUsers[role2], user)
		RoleUsers[role3] = append(RoleUsers[role3], user)
		RoleUsers[role5] = append(RoleUsers[role5], user)
	}
}

var ObjectGroupings = []struct {
	Art types.Article
	Cat types.Category
}{
	{Art: types.Article("project apollo"), Cat: types.Category("peace")},
	{Art: types.Article("manhattan project"), Cat: types.Category("war")},
	{Art: types.Article("operation market garden"), Cat: types.Category("war")},
	{Art: types.Article("operation overlord"), Cat: types.Category("war")},

	{Art: types.Article("project apollo"), Cat: types.Category("america")},
	{Art: types.Article("manhattan project"), Cat: types.Category("america")},
	{Art: types.Article("operation market garden"), Cat: types.Category("europe")},
	{Art: types.Article("operation overlord"), Cat: types.Category("europe")},

	{Art: types.Article("project apollo"), Cat: types.Category("success")},
	{Art: types.Article("manhattan project"), Cat: types.Category("success")},
	{Art: types.Article("operation market garden"), Cat: types.Category("success")},
	{Art: types.Article("operation overlord"), Cat: types.Category("fail")},
}

var UserToArticlePolices = []struct {
	Sub types.User
	Obj types.Article
	Act types.Action
}{}

var UserToCategoryPolices = []struct {
	Sub types.User
	Obj types.Category
	Act types.Action
}{
	{Sub: types.User("0"), Obj: types.Category("war"), Act: types.Read},
	{Sub: types.User("0"), Obj: types.Category("peace"), Act: types.ReadWrite},
	{Sub: types.User("0"), Obj: types.Category("fail"), Act: types.Read},
	{Sub: types.User("1"), Obj: types.Category("europe"), Act: types.ReadExec},
	{Sub: types.User("2"), Obj: types.Category("fail"), Act: types.ReadWrite},
	{Sub: types.User("3"), Obj: types.Category("war"), Act: types.ReadExec},
}

var RoleToArticlePolices = []struct {
	Sub types.Role
	Obj types.Article
	Act types.Action
}{
	{Sub: types.Role("2_0"), Obj: types.Article("project apollo"), Act: types.Read},
	{Sub: types.Role("2_1"), Obj: types.Article("project apollo"), Act: types.ReadWriteExec},
	{Sub: types.Role("3_0"), Obj: types.Article("manhattan project"), Act: types.Read},
	{Sub: types.Role("3_1"), Obj: types.Article("manhattan project"), Act: types.ReadWrite},
	{Sub: types.Role("3_2"), Obj: types.Article("manhattan project"), Act: types.ReadExec},
}

var RoleToCategoryPolices = []struct {
	Sub types.Role
	Obj types.Category
	Act types.Action
}{
	{Sub: types.Role("2_0"), Obj: types.Category("europe"), Act: types.Read},
	{Sub: types.Role("2_1"), Obj: types.Category("europe"), Act: types.ReadWriteExec},
	{Sub: types.Role("3_0"), Obj: types.Category("war"), Act: types.Read},
	{Sub: types.Role("3_1"), Obj: types.Category("war"), Act: types.ReadWrite},
	{Sub: types.Role("3_2"), Obj: types.Category("war"), Act: types.ReadExec},
}
