package repository

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/stretchr/testify/require"
)

// TestIntegration_RepoSurface exercises most Store methods (requires Docker).
func TestIntegration_RepoSurface(t *testing.T) {
	s, cleanup := setupRepo(t)
	defer cleanup()
	ctx := context.Background()
	require.NoError(t, s.Ping(ctx))

	humanID, err := s.CreateHumanUser(ctx, "surf", "surf@test.dev", "ph")
	require.NoError(t, err)
	svcID, err := s.CreateServiceUser(ctx, "svc1", "secrethash")
	require.NoError(t, err)

	u, err := s.GetUserByID(ctx, humanID)
	require.NoError(t, err)
	require.NotNil(t, u)
	require.NoError(t, s.SetLockedUntil(ctx, humanID, ptrTime(time.Now().Add(time.Minute))))
	require.NoError(t, s.SetLockedUntil(ctx, humanID, nil))

	require.NoError(t, s.InsertPasswordHistory(ctx, humanID, "h1", []byte("c1"), []byte("n1")))
	hist, err := s.ListPasswordHistory(ctx, humanID, 5)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(hist), 1)
	require.NoError(t, s.TrimPasswordHistory(ctx, humanID, 0))

	users, err := s.ListUsers(ctx, 10)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(users), 2)

	roleID, err := s.CreateRole(ctx, "r1", "d1")
	require.NoError(t, err)
	rn, err := s.GetRoleByName(ctx, "r1")
	require.NoError(t, err)
	require.NotNil(t, rn)
	ri, err := s.GetRoleByID(ctx, roleID)
	require.NoError(t, err)
	require.NotNil(t, ri)
	roles, err := s.ListRoles(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, roles)
	require.NoError(t, s.UpdateRoleDescription(ctx, roleID, "d2"))

	require.NoError(t, s.AssignUserRole(ctx, humanID, roleID, domain.RoleMember, &humanID, time.Now(), nil))
	lvl, ok, err := s.GetUserRoleLevel(ctx, humanID, roleID, time.Now())
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, domain.RoleMember, lvl)
	urs, err := s.ListUserRoles(ctx, humanID, time.Now())
	require.NoError(t, err)
	require.NotEmpty(t, urs)

	n, err := s.CountFailedLogins(ctx, "surf", time.Now().Add(-time.Hour))
	require.NoError(t, err)
	require.Equal(t, int64(0), n)
	require.NoError(t, s.InsertFailedLogin(ctx, "surf", net.ParseIP("127.0.0.1")))
	n, err = s.CountFailedLogins(ctx, "surf", time.Now().Add(-time.Hour))
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, int64(1))
	require.NoError(t, s.DeleteOldFailedLogins(ctx, time.Now().Add(time.Hour)))

	otpID, err := s.CreateEmailOTP(ctx, humanID, domain.OTPLogin, []byte("hash"), time.Now().Add(time.Minute), nil)
	require.NoError(t, err)
	latest, err := s.GetLatestOTP(ctx, humanID, domain.OTPLogin)
	require.NoError(t, err)
	require.NotNil(t, latest)
	corr := "corr-1"
	_, err = s.CreateEmailOTP(ctx, humanID, domain.OTPStepUp2FA, []byte("h2"), time.Now().Add(time.Minute), &corr)
	require.NoError(t, err)
	byc, err := s.GetOTPByCorrelation(ctx, corr)
	require.NoError(t, err)
	require.NotNil(t, byc)
	require.NoError(t, s.IncrementOTPAttempt(ctx, otpID))
	require.NoError(t, s.ConsumeOTP(ctx, otpID))
	require.Error(t, s.ConsumeOTP(ctx, otpID))

	require.NoError(t, s.InsertSigningKey(ctx, "sk-old", []byte("c1"), []byte("n1"), false))
	require.NoError(t, s.InsertSigningKey(ctx, "sk-new", []byte("c2"), []byte("n2"), true))
	cnt, err := s.CountSigningKeys(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, cnt, int64(2))
	cur, err := s.GetCurrentSigningKeyMaterial(ctx)
	require.NoError(t, err)
	require.NotNil(t, cur)
	one, err := s.GetSigningKeyMaterial(ctx, "sk-old")
	require.NoError(t, err)
	require.NotNil(t, one)
	require.NoError(t, s.DeprecateCurrentAndSet(ctx, "sk-third", []byte("c3"), []byte("n3")))

	exp := time.Now().Add(time.Hour)
	tok := []byte{1, 2, 3, 4}
	_, err = s.UpsertRefreshSession(ctx, humanID, "d1", "lbl", tok, exp)
	require.NoError(t, err)
	c, err := s.CountActiveRefreshSessions(ctx, humanID)
	require.NoError(t, err)
	require.GreaterOrEqual(t, c, int64(1))
	row, err := s.GetRefreshByUserDevice(ctx, humanID, "d1")
	require.NoError(t, err)
	require.NotNil(t, row)
	sessions, err := s.ListRefreshSessions(ctx, humanID)
	require.NoError(t, err)
	require.NotEmpty(t, sessions)
	require.NoError(t, s.MarkRefreshUsed(ctx, row.ID))
	require.NoError(t, s.RevokeRefreshSession(ctx, row.ID))

	tok2 := []byte{5, 6, 7, 8}
	rid2, err := s.UpsertRefreshSession(ctx, svcID, "d2", "", tok2, exp)
	require.NoError(t, err)
	require.NoError(t, s.RevokeRefreshByHash(ctx, svcID, tok2))
	_, err = s.GetRefreshByID(ctx, rid2)
	require.NoError(t, err)

	require.NoError(t, s.CreateStepUp2FASession(ctx, "grpc-corr", humanID, time.Now().Add(time.Minute)))
	g2, err := s.GetStepUp2FA(ctx, "grpc-corr")
	require.NoError(t, err)
	require.NotNil(t, g2)
	require.NoError(t, s.ApproveStepUp2FA(ctx, "grpc-corr"))
	require.NoError(t, s.CreateStepUp2FASession(ctx, "grpc-corr2", humanID, time.Now().Add(time.Minute)))
	require.NoError(t, s.ExpireStepUp2FA(ctx, "grpc-corr2"))
	require.NoError(t, s.CreateStepUp2FASession(ctx, "grpc-corr3", humanID, time.Now().Add(-time.Second)))
	require.NoError(t, s.MarkExpiredStepUp2FAByTime(ctx, time.Now()))

	reqID, err := s.CreateRoleRequest(ctx, humanID, svcID, roleID)
	require.NoError(t, err)
	pending, err := s.ListPendingRoleRequests(ctx, roleID)
	require.NoError(t, err)
	require.NotEmpty(t, pending)
	got, err := s.GetRoleRequest(ctx, reqID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NoError(t, s.DecideRoleRequest(ctx, reqID, false, humanID))

	require.NoError(t, s.RemoveUserRole(ctx, humanID, roleID))
	has, err := s.UserHasRoleName(ctx, humanID, "r1", time.Now())
	require.NoError(t, err)
	require.False(t, has)

	require.NoError(t, s.UpdatePassword(ctx, humanID, "newhash"))
}

func TestIntegration_UpsertReplaceRefresh(t *testing.T) {
	s, cleanup := setupRepo(t)
	defer cleanup()
	ctx := context.Background()
	uid, err := s.CreateHumanUser(ctx, "tok", "tok@test.dev", "x")
	require.NoError(t, err)
	exp := time.Now().Add(time.Hour)
	h1 := []byte{1, 1, 1}
	id1, err := s.UpsertRefreshSession(ctx, uid, "dev", "", h1, exp)
	require.NoError(t, err)
	h2 := []byte{2, 2, 2}
	id2, err := s.UpsertRefreshSession(ctx, uid, "dev", "x", h2, exp)
	require.NoError(t, err)
	require.Equal(t, id1, id2)
	found, err := s.FindRefreshByTokenHash(ctx, h2)
	require.NoError(t, err)
	require.NotNil(t, found)
	h3 := []byte{3, 3, 3}
	require.NoError(t, s.ReplaceRefreshToken(ctx, found.ID, h2, h3, exp.Add(time.Hour)))
}

func TestIntegration_RoleRequestApprove(t *testing.T) {
	s, cleanup := setupRepo(t)
	defer cleanup()
	ctx := context.Background()
	a, err := s.CreateHumanUser(ctx, "ra", "ra@test.dev", "x")
	require.NoError(t, err)
	b, err := s.CreateHumanUser(ctx, "rb", "rb@test.dev", "x")
	require.NoError(t, err)
	rid, err := s.CreateRole(ctx, "rr", "")
	require.NoError(t, err)
	reqID, err := s.CreateRoleRequest(ctx, a, b, rid)
	require.NoError(t, err)
	require.NoError(t, s.DecideRoleRequest(ctx, reqID, true, a))
	require.NoError(t, s.AssignUserRole(ctx, b, rid, domain.RoleMember, &a, time.Now(), nil))
	ok, err := s.UserHasRoleName(ctx, b, "rr", time.Now())
	require.NoError(t, err)
	require.True(t, ok)
}
