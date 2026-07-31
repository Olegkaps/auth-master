package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/stretchr/testify/require"
)

// A role admin of a parent role is automatically a role admin (and can assign)
// on descendant roles, but not the other way around.
func TestIntegration_RoleHierarchyInheritedAdmin(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{}, nil)
	require.NoError(t, err)

	uid, err := repo.CreateHumanUser(ctx, "parentadmin", "pa@test.dev", "h")
	require.NoError(t, err)

	parent, err := repo.CreateRole(ctx, "org", "top", nil)
	require.NoError(t, err)
	child, err := repo.CreateRole(ctx, "team", "under org", &parent)
	require.NoError(t, err)
	grandchild, err := repo.CreateRole(ctx, "squad", "under team", &child)
	require.NoError(t, err)

	// Admin only on the parent role.
	require.NoError(t, repo.AssignUserRole(ctx, uid, parent, domain.RoleRoleAdmin, &uid, time.Now(), nil))

	// Inherited admin flows down the whole chain.
	adminParent, _ := a.IsRoleAdmin(ctx, uid, parent)
	adminChild, _ := a.IsRoleAdmin(ctx, uid, child)
	adminGrand, _ := a.IsRoleAdmin(ctx, uid, grandchild)
	require.True(t, adminParent)
	require.True(t, adminChild, "admin of parent should inherit admin on child")
	require.True(t, adminGrand, "admin of parent should inherit admin on grandchild")

	canChild, _ := a.CanAssignRole(ctx, uid, child)
	require.True(t, canChild)

	// A separate user who is admin only on the child must NOT gain admin on parent.
	other, err := repo.CreateHumanUser(ctx, "childadmin", "ca@test.dev", "h")
	require.NoError(t, err)
	require.NoError(t, repo.AssignUserRole(ctx, other, child, domain.RoleRoleAdmin, &other, time.Now(), nil))
	upAdmin, _ := a.IsRoleAdmin(ctx, other, parent)
	require.False(t, upAdmin, "admin of child must not inherit admin on parent")
	downAdmin, _ := a.IsRoleAdmin(ctx, other, grandchild)
	require.True(t, downAdmin, "admin of child inherits admin on grandchild")
}

// Setting a parent that is the role itself or a descendant is a cycle and must
// be rejected by the RoleHasAncestor guard the handler relies on.
func TestIntegration_RoleHierarchyCycleGuard(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()

	a, err := repo.CreateRole(ctx, "a", "", nil)
	require.NoError(t, err)
	b, err := repo.CreateRole(ctx, "b", "", &a)
	require.NoError(t, err)

	// b's ancestors include a and b — so making a a child of b (parent=b) is a cycle.
	cycle, err := repo.RoleHasAncestor(ctx, b, a)
	require.NoError(t, err)
	require.True(t, cycle)

	// Making a a child of an unrelated fresh role is fine.
	c, err := repo.CreateRole(ctx, "c", "", nil)
	require.NoError(t, err)
	noCycle, err := repo.RoleHasAncestor(ctx, c, a)
	require.NoError(t, err)
	require.False(t, noCycle)
	require.NoError(t, repo.SetRoleParent(ctx, a, &c))
}

// A role can be mounted under several parents and inherits membership and
// administrator authority independently through every path.
func TestIntegration_RoleHierarchyMultipleParents(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	auth, err := NewAuth(testConfig(), repo, &mail.Sender{}, nil)
	require.NoError(t, err)

	left, err := repo.CreateRole(ctx, "left-parent", "", nil)
	require.NoError(t, err)
	right, err := repo.CreateRole(ctx, "right-parent", "", nil)
	require.NoError(t, err)
	child, err := repo.CreateRole(ctx, "mounted-child", "", &left)
	require.NoError(t, err)
	require.NoError(t, repo.MountRole(ctx, child, right))

	leftUser, err := repo.CreateHumanUser(ctx, "left-user", "left@test.dev", "h")
	require.NoError(t, err)
	rightAdmin, err := repo.CreateHumanUser(ctx, "right-admin", "right@test.dev", "h")
	require.NoError(t, err)
	require.NoError(t, repo.AssignUserRole(ctx, leftUser, left, domain.RoleMember, &leftUser, time.Now(), nil))
	require.NoError(t, repo.AssignUserRole(ctx, rightAdmin, right, domain.RoleRoleAdmin, &rightAdmin, time.Now(), nil))

	hasChild, err := auth.UserHasRoleName(ctx, leftUser, "mounted-child")
	require.NoError(t, err)
	require.True(t, hasChild)
	managesChild, err := auth.IsRoleAdmin(ctx, rightAdmin, child)
	require.NoError(t, err)
	require.True(t, managesChild)

	roles, err := repo.ListRoles(ctx)
	require.NoError(t, err)
	for _, role := range roles {
		if role.ID == child {
			require.ElementsMatch(t, []uuid.UUID{left, right}, role.ParentIDs)
		}
	}

	require.NoError(t, repo.UnmountRole(ctx, child, right))
	managesChild, err = auth.IsRoleAdmin(ctx, rightAdmin, child)
	require.NoError(t, err)
	require.False(t, managesChild)
}
