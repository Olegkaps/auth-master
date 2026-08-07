package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/jwtutil"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/stretchr/testify/require"
)

func TestIntegration_BanRevokesExistingAuthorizationAndUnbanRestoresLogin(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{}, nil)
	require.NoError(t, err)
	require.NoError(t, a.EnsureBootstrap(ctx))

	invite := seedSuperInvite(t, a, repo, ctx)
	admin, err := repo.GetUserByLogin(ctx, "invite-admin")
	require.NoError(t, err)
	require.NotNil(t, admin)
	userID, err := a.Register(ctx, invite, "ban-live", "ban-live@test.dev", "Ban-Live-Password-11!")
	require.NoError(t, err)
	tokens := loginFull(t, a, repo, ctx, "ban-live", "Ban-Live-Password-11!", "ban-live-device")

	active, err := repo.CountActiveRefreshSessions(ctx, userID)
	require.NoError(t, err)
	require.EqualValues(t, 1, active)
	require.NoError(t, a.BanUser(ctx, admin.ID, userID, "incident"))

	_, err = a.VerifyAccessToken(ctx, tokens.AccessToken, jwtutil.TypeAccess)
	require.ErrorIs(t, err, ErrBanned)
	_, err = a.Refresh(ctx, tokens.RefreshToken, "ban-live-device", "browser")
	require.Error(t, err)
	active, err = repo.CountActiveRefreshSessions(ctx, userID)
	require.NoError(t, err)
	require.Zero(t, active)
	_, err = a.LoginPassword(ctx, "ban-live", "Ban-Live-Password-11!", nil)
	require.ErrorIs(t, err, ErrBanned)

	require.NoError(t, a.UnbanUser(ctx, admin.ID, userID))
	login, err := a.LoginPassword(ctx, "ban-live", "Ban-Live-Password-11!", nil)
	require.NoError(t, err)
	require.True(t, login.OTPRequired)
}

func TestIntegration_BanAuthorizationBoundaries(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{}, nil)
	require.NoError(t, err)

	adminID, err := repo.CreateHumanUser(ctx, "ban-admin", "ban-admin@test.dev", "hash")
	require.NoError(t, err)
	require.NoError(t, repo.SetSuperuser(ctx, adminID, true))
	ordinaryID, err := repo.CreateHumanUser(ctx, "ban-ordinary", "ban-ordinary@test.dev", "hash")
	require.NoError(t, err)
	targetID, err := repo.CreateHumanUser(ctx, "ban-target", "ban-target@test.dev", "hash")
	require.NoError(t, err)

	require.ErrorIs(t, a.BanUser(ctx, ordinaryID, targetID, "not allowed"), ErrForbidden)
	require.ErrorIs(t, a.BanUser(ctx, adminID, adminID, "self"), ErrCannotBanSelf)
	require.ErrorIs(t, a.BanUser(ctx, adminID, uuid.New(), "missing"), ErrNotFound)
	require.ErrorIs(t, a.BanUser(ctx, adminID, adminID, "superuser"), ErrCannotBanSelf)

	otherSuperID, err := repo.CreateHumanUser(ctx, "ban-super", "ban-super@test.dev", "hash")
	require.NoError(t, err)
	require.NoError(t, repo.SetSuperuser(ctx, otherSuperID, true))
	require.ErrorIs(t, a.BanUser(ctx, adminID, otherSuperID, "superuser"), ErrCannotBanSuperuser)
	require.ErrorIs(t, a.UnbanUser(ctx, ordinaryID, targetID), ErrForbidden)
	require.ErrorIs(t, a.UnbanUser(ctx, adminID, uuid.New()), ErrNotFound)

	require.NoError(t, repo.SetUserBan(ctx, targetID, &adminID, "temporary"))
	require.NoError(t, a.UnbanUser(ctx, adminID, targetID))
	target, err := repo.GetUserByID(ctx, targetID)
	require.NoError(t, err)
	require.Nil(t, target.BannedAt)
	require.Empty(t, target.BanReason)
}
