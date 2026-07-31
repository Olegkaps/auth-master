package service

import (
	"context"
	"testing"
	"time"

	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/stretchr/testify/require"
)

func TestIntegration_RBACHelpers(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	m := &mail.Sender{}
	a, err := NewAuth(testConfig(), repo, m, nil)
	require.NoError(t, err)

	uid, err := repo.CreateHumanUser(ctx, "rbac", "rbac@test.dev", "h")
	require.NoError(t, err)
	ok, err := a.IsSuperuser(ctx, uid)
	require.NoError(t, err)
	require.False(t, ok)

	rid, err := repo.CreateRole(ctx, "adm", "", nil)
	require.NoError(t, err)
	require.NoError(t, repo.AssignUserRole(ctx, uid, rid, domain.RoleRoleAdmin, &uid, time.Now(), nil))

	su, err := a.IsSuperuser(ctx, uid)
	require.NoError(t, err)
	require.False(t, su)
	ra, err := a.IsRoleAdmin(ctx, uid, rid)
	require.NoError(t, err)
	require.True(t, ra)
	can, err := a.CanAssignRole(ctx, uid, rid)
	require.NoError(t, err)
	require.True(t, can)
	has, err := a.UserHasRoleName(ctx, uid, "adm")
	require.NoError(t, err)
	require.True(t, has)
	view, err := a.CanViewUserRoles(ctx, uid, uid)
	require.NoError(t, err)
	require.True(t, view)

	peer, err := repo.CreateHumanUser(ctx, "rbac-peer", "rbacpeer@test.dev", "h")
	require.NoError(t, err)
	viewOther, err := a.CanViewUserRoles(ctx, uid, peer)
	require.NoError(t, err)
	require.False(t, viewOther)
}
