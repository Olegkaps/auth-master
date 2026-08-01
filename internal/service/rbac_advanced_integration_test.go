package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/stretchr/testify/require"
)

// has-role and role-admin authority propagate down the hierarchy to arbitrary
// depth, live — reflecting roles/edges created or changed after the membership.
func TestIntegration_HierarchyPropagationDepthN(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{}, nil)
	require.NoError(t, err)

	const n = 6
	names := make([]string, n)
	ids := make([]uuid.UUID, n)
	var parent *uuid.UUID
	sfx := uuid.NewString()[:8]
	for i := 0; i < n; i++ {
		names[i] = fmt.Sprintf("h%d-%s", i, sfx)
		id, err := repo.CreateRole(ctx, names[i], "", parent)
		require.NoError(t, err)
		ids[i] = id
		p := id
		parent = &p
	}

	admin, err := repo.CreateHumanUser(ctx, "chain-admin-"+sfx, "ca"+sfx+"@test.dev", "h")
	require.NoError(t, err)
	require.NoError(t, repo.AssignUserRole(ctx, admin, ids[0], domain.RoleRoleAdmin, &admin, time.Now(), nil))

	// Admin of the root inherits has-role AND management at every depth.
	for i := 0; i < n; i++ {
		has, err := a.UserHasRoleName(ctx, admin, names[i])
		require.NoError(t, err)
		require.Truef(t, has, "has-role must propagate to depth %d", i)
		isAdmin, err := a.IsRoleAdmin(ctx, admin, ids[i])
		require.NoError(t, err)
		require.Truef(t, isAdmin, "management must propagate to depth %d", i)
	}

	// A plain member of the root gets has-role down the chain but NOT management.
	member, err := repo.CreateHumanUser(ctx, "chain-member-"+sfx, "cm"+sfx+"@test.dev", "h")
	require.NoError(t, err)
	require.NoError(t, repo.AssignUserRole(ctx, member, ids[0], domain.RoleMember, &member, time.Now(), nil))
	hasLeaf, _ := a.UserHasRoleName(ctx, member, names[n-1])
	require.True(t, hasLeaf, "plain member's has-role propagates down")
	admLeaf, _ := a.IsRoleAdmin(ctx, member, ids[n-1])
	require.False(t, admLeaf, "plain membership does not grant management")

	// Dynamic: a child added AFTER the membership is covered immediately.
	newChildName := "late-child-" + sfx
	newChild, err := repo.CreateRole(ctx, newChildName, "", &ids[n-1])
	require.NoError(t, err)
	hasNew, _ := a.UserHasRoleName(ctx, admin, newChildName)
	require.True(t, hasNew, "role created after membership is still covered")
	admNew, _ := a.IsRoleAdmin(ctx, admin, newChild)
	require.True(t, admNew)

	// Dynamic: detaching a mid-node stops propagation below it, but the root
	// membership itself is unaffected.
	require.NoError(t, repo.SetRoleParent(ctx, ids[1], nil))
	hasAfterDetach, _ := a.UserHasRoleName(ctx, admin, names[1])
	require.False(t, hasAfterDetach, "detached subtree is no longer covered")
	hasRoot, _ := a.UserHasRoleName(ctx, admin, names[0])
	require.True(t, hasRoot)
}

// A manager's membership request is auto-granted; a non-manager's is pending.
func TestIntegration_RequestRoleMembershipAutoApprove(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{}, nil)
	require.NoError(t, err)
	sfx := uuid.NewString()[:8]

	su, err := repo.CreateHumanUser(ctx, "su-"+sfx, "su"+sfx+"@test.dev", "h")
	require.NoError(t, err)
	require.NoError(t, repo.SetSuperuser(ctx, su, true))
	parent, err := repo.CreateRole(ctx, "p-"+sfx, "", nil)
	require.NoError(t, err)
	child, err := repo.CreateRole(ctx, "c-"+sfx, "", &parent)
	require.NoError(t, err)

	// Superuser → granted immediately.
	t1, _ := repo.CreateHumanUser(ctx, "t1-"+sfx, "t1"+sfx+"@test.dev", "h")
	granted, _, err := a.RequestRoleMembership(ctx, su, t1, child)
	require.NoError(t, err)
	require.True(t, granted)
	_, ok, _ := repo.GetUserRoleLevel(ctx, t1, child, time.Now())
	require.True(t, ok)

	// Non-manager requesting for self → pending request, no membership.
	plain, _ := repo.CreateHumanUser(ctx, "plain-"+sfx, "pl"+sfx+"@test.dev", "h")
	granted2, reqID, err := a.RequestRoleMembership(ctx, plain, plain, child)
	require.NoError(t, err)
	require.False(t, granted2)
	require.NotEqual(t, uuid.Nil, reqID)
	_, ok2, _ := repo.GetUserRoleLevel(ctx, plain, child, time.Now())
	require.False(t, ok2)

	// Admin of the PARENT role manages the child (via hierarchy) → granted.
	mgr, _ := repo.CreateHumanUser(ctx, "mgr-"+sfx, "mgr"+sfx+"@test.dev", "h")
	require.NoError(t, repo.AssignUserRole(ctx, mgr, parent, domain.RoleRoleAdmin, &mgr, time.Now(), nil))
	t2, _ := repo.CreateHumanUser(ctx, "t2-"+sfx, "t2"+sfx+"@test.dev", "h")
	granted3, _, err := a.RequestRoleMembership(ctx, mgr, t2, child)
	require.NoError(t, err)
	require.True(t, granted3, "ancestor-role admin is a manager and needs no approval")
}

// Deleting a role removes its memberships/requests and re-parents its children.
func TestIntegration_DeleteRoleReparentsAndCascades(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	sfx := uuid.NewString()[:8]
	now := time.Now()

	parent, err := repo.CreateRole(ctx, "dp-"+sfx, "", nil)
	require.NoError(t, err)
	child, err := repo.CreateRole(ctx, "dc-"+sfx, "", &parent)
	require.NoError(t, err)
	grand, err := repo.CreateRole(ctx, "dg-"+sfx, "", &child)
	require.NoError(t, err)

	u, _ := repo.CreateHumanUser(ctx, "du-"+sfx, "du"+sfx+"@test.dev", "h")
	require.NoError(t, repo.AssignUserRole(ctx, u, child, domain.RoleMember, &u, now, nil))
	_, err = repo.CreateRoleRequest(ctx, u, u, child)
	require.NoError(t, err)

	require.NoError(t, repo.DeleteRole(ctx, child))

	// Grandchild re-parented to the deleted role's parent.
	g, err := repo.GetRoleByID(ctx, grand)
	require.NoError(t, err)
	require.NotNil(t, g.ParentID)
	require.Equal(t, parent, *g.ParentID)

	// Membership and role are gone.
	_, ok, _ := repo.GetUserRoleLevel(ctx, u, child, now)
	require.False(t, ok)
	c, err := repo.GetRoleByID(ctx, child)
	require.NoError(t, err)
	require.Nil(t, c)
}
