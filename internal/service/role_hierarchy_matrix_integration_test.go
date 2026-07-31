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

// Exhaustive matrix for has-role and role-manager resolution across every
// relationship between a user's membership role and the queried role, for both
// membership levels. Authority (management) and role possession (has-role) both
// flow DOWN the hierarchy (ancestor → descendant), never up or sideways.
//
// Hierarchy used:  grandparent → parent → child   and a separate  unrelated.
func TestIntegration_RoleHierarchyMatrix(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{}, nil)
	require.NoError(t, err)
	sfx := uuid.NewString()[:8]

	mk := func(name string, parent *uuid.UUID) (uuid.UUID, string) {
		full := name + "-" + sfx
		id, e := repo.CreateRole(ctx, full, "", parent)
		require.NoError(t, e)
		return id, full
	}
	gp, gpName := mk("gp", nil)
	par, parName := mk("par", &gp)
	ch, chName := mk("ch", &par)
	un, unName := mk("un", nil)

	// helper user with a single membership at `role` and `level`.
	mkUser := func(tag string, role uuid.UUID, level domain.RoleLevel) uuid.UUID {
		id, e := repo.CreateHumanUser(ctx, tag+"-"+sfx, tag+sfx+"@test.dev", "h")
		require.NoError(t, e)
		require.NoError(t, repo.AssignUserRole(ctx, id, role, level, &id, time.Now(), nil))
		return id
	}
	hasRole := func(u uuid.UUID, name string) bool {
		ok, e := a.UserHasRoleName(ctx, u, name)
		require.NoError(t, e)
		return ok
	}
	isMgr := func(u, role uuid.UUID) bool { ok, e := a.IsRoleAdmin(ctx, u, role); require.NoError(t, e); return ok }

	type roleRef struct {
		id   uuid.UUID
		name string
	}
	all := []roleRef{{gp, gpName}, {par, parName}, {ch, chName}, {un, unName}}

	// --- Member at the PARENT role ------------------------------------------
	// has-role: true for parent (self) and child (descendant); false for
	// grandparent (ancestor) and unrelated. Management: false everywhere.
	member := mkUser("member-par", par, domain.RoleMember)
	wantHasMember := map[uuid.UUID]bool{gp: false, par: true, ch: true, un: false}
	for _, r := range all {
		require.Equalf(t, wantHasMember[r.id], hasRole(member, r.name), "member@parent has-role %s", r.name)
		require.Falsef(t, isMgr(member, r.id), "plain member is never a manager (%s)", r.name)
	}

	// --- role_admin at the PARENT role --------------------------------------
	// has-role: same as membership (parent + child). Management: true for parent
	// (self) and child (descendant); false for grandparent (up) and unrelated.
	admin := mkUser("admin-par", par, domain.RoleRoleAdmin)
	wantHasAdmin := map[uuid.UUID]bool{gp: false, par: true, ch: true, un: false}
	wantMgrAdmin := map[uuid.UUID]bool{gp: false, par: true, ch: true, un: false}
	for _, r := range all {
		require.Equalf(t, wantHasAdmin[r.id], hasRole(admin, r.name), "admin@parent has-role %s", r.name)
		require.Equalf(t, wantMgrAdmin[r.id], isMgr(admin, r.id), "admin@parent manages %s", r.name)
	}

	// --- role_admin at the CHILD (leaf) role --------------------------------
	// Nothing below the child, so management is only the child itself; parent and
	// grandparent (ancestors) are NOT managed (authority doesn't flow up).
	leafAdmin := mkUser("admin-ch", ch, domain.RoleRoleAdmin)
	wantMgrLeaf := map[uuid.UUID]bool{gp: false, par: false, ch: true, un: false}
	wantHasLeaf := map[uuid.UUID]bool{gp: false, par: false, ch: true, un: false}
	for _, r := range all {
		require.Equalf(t, wantHasLeaf[r.id], hasRole(leafAdmin, r.name), "admin@child has-role %s", r.name)
		require.Equalf(t, wantMgrLeaf[r.id], isMgr(leafAdmin, r.id), "admin@child manages %s", r.name)
	}

	// --- edge cases ---------------------------------------------------------
	// Superuser is a manager of every role but holds no roles by name.
	su, _ := repo.CreateHumanUser(ctx, "su-mx-"+sfx, "sumx"+sfx+"@test.dev", "h")
	require.NoError(t, repo.SetSuperuser(ctx, su, true))
	for _, r := range all {
		can, e := a.CanAssignRole(ctx, su, r.id)
		require.NoError(t, e)
		require.Truef(t, can, "superuser manages every role (%s)", r.name)
	}

	// Non-existent role name → has-role false.
	require.False(t, hasRole(member, "no-such-role-"+sfx))

	// Expired membership → neither has-role nor management.
	expUser, _ := repo.CreateHumanUser(ctx, "exp-mx-"+sfx, "expmx"+sfx+"@test.dev", "h")
	pastUntil := time.Now().Add(-time.Minute)
	require.NoError(t, repo.AssignUserRole(ctx, expUser, par, domain.RoleRoleAdmin, &expUser, time.Now().Add(-time.Hour), &pastUntil))
	require.False(t, hasRole(expUser, parName), "expired membership grants nothing")
	require.False(t, hasRole(expUser, chName))
	require.False(t, isMgr(expUser, ch))
}
