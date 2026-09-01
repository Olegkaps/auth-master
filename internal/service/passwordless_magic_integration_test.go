package service

import (
	"context"
	"testing"
	"time"

	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/jwtutil"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/stretchr/testify/require"
)

func TestIntegration_PasswordlessMagicSessionHasNormalAuthorizationAndOptionalReset(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{Host: "localhost", Port: 1025, From: "t@test.dev"}, nil)
	require.NoError(t, err)
	require.NoError(t, a.EnsureBootstrap(ctx))
	uid, err := repo.CreatePasswordlessHuman(ctx, "MiGrAtEd", "Mixed@Example.Test")
	require.NoError(t, err)
	require.NoError(t, repo.SetSuperuser(ctx, uid, true))
	roleID, err := repo.CreateRole(ctx, "admin", "", nil)
	require.NoError(t, err)
	require.NoError(t, repo.AssignUserRole(ctx, uid, roleID, domain.RoleMember, nil, time.Now(), nil))

	loginByMagic := func(token, device string) *TokenPair {
		t.Helper()
		_, insertErr := repo.InsertMagicLink(ctx, a.IntegrationMagicHash(token), uid, time.Now().Add(time.Minute))
		require.NoError(t, insertErr)
		pair, user, completeErr := a.CompleteMagicLink(ctx, token, device, "browser")
		require.NoError(t, completeErr)
		require.Nil(t, user.PasswordHash)
		return pair
	}

	pair := loginByMagic("passwordless-first-magic", "device-one")
	_, err = a.LoginPassword(ctx, "MIXED@example.test", "legacy-password-must-not-work", nil)
	require.ErrorIs(t, err, ErrInvalidCredentials)
	_, err = a.VerifyAccessToken(ctx, pair.AccessToken, jwtutil.TypeAccess)
	require.NoError(t, err)
	_, err = a.VerifyAccessOrServiceToken(ctx, pair.AccessToken)
	require.NoError(t, err)
	has, err := a.UserHasRoleName(ctx, uid, "admin")
	require.NoError(t, err)
	require.True(t, has)
	superuser, err := a.IsSuperuser(ctx, uid)
	require.NoError(t, err)
	require.True(t, superuser)

	require.NoError(t, a.Logout(ctx, pair.RefreshToken))
	second := loginByMagic("passwordless-second-magic", "device-two")
	_, err = a.VerifyAccessToken(ctx, second.AccessToken, jwtutil.TypeAccess)
	require.NoError(t, err, "passwordless magic login may be repeated indefinitely")

	// Password reset is optional, but available without an existing password.
	require.NoError(t, a.StartPasswordReset(ctx, " MIXED@EXAMPLE.TEST "))
	require.NoError(t, a.Shutdown(ctx), "drain the private delivery worker before inspecting persistence")
	issued, err := repo.GetMostRecentOTP(ctx, uid, domain.OTPPasswordReset)
	require.NoError(t, err)
	require.NotNil(t, issued)
	require.Nil(t, issued.ConsumedAt, "a delivered reset code is activated")
	code := "481516"
	_, active, err := repo.IssuePasswordResetOTP(ctx, uid, a.IntegrationOTPHash(code), time.Now(), time.Now().Add(time.Minute), 0)
	require.NoError(t, err)
	require.True(t, active)
	require.NoError(t, a.ResetPasswordWithOTP(ctx, " MIXED@EXAMPLE.TEST ", code, "New-Migrated9!"))
	passwordLogin, err := a.LoginPassword(ctx, "MIXED@example.test", "New-Migrated9!", nil)
	require.NoError(t, err)
	require.True(t, passwordLogin.OTPRequired)
}
