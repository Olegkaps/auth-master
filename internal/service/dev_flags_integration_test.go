package service

import (
	"context"
	"testing"
	"time"

	"github.com/olegkapshai/auth-master/internal/crypto"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestIntegration_OpenRegistrationAndSkippedLoginOTP(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	cfg := testConfig()
	cfg.RegistrationOpen = true
	cfg.SkipLoginOTP = true
	mailer := &countingMailer{}
	auth, err := NewAuth(cfg, repo, mailer, nil)
	require.NoError(t, err)
	require.NoError(t, auth.EnsureBootstrap(ctx))

	userID, err := auth.Register(ctx, "", "  Open-User  ", "  OPEN-USER@EXAMPLE.TEST ", "Open-User-Password1!")
	require.NoError(t, err)
	user, err := repo.GetUserByID(ctx, userID)
	require.NoError(t, err)
	require.Equal(t, "open-user", user.Login)
	require.Equal(t, "open-user@example.test", *user.Email)
	require.Equal(t, domain.UserHuman, user.Kind)
	require.False(t, user.Superuser)
	require.NotNil(t, user.PasswordHash)
	passwordOK, err := crypto.VerifyPassword("Open-User-Password1!", *user.PasswordHash)
	require.NoError(t, err)
	require.True(t, passwordOK)
	history, err := repo.ListPasswordHistory(ctx, userID, 10)
	require.NoError(t, err)
	require.Len(t, history, 1)

	_, err = auth.Register(ctx, "invalid-explicit-token", "strict-user", "strict@example.test", "Strict-User-Password1!")
	require.ErrorIs(t, err, ErrInvalidInvite)

	login, err := auth.LoginPassword(ctx, "OPEN-USER@EXAMPLE.TEST", "Open-User-Password1!", nil)
	require.NoError(t, err)
	require.False(t, login.OTPRequired)
	require.Zero(t, mailer.calls, "skipped login OTP must not send a code email")
	tokens, signedInUser, err := auth.LoginVerifyOTP(ctx, login.LoginChallenge, "", "open-device", "integration")
	require.NoError(t, err)
	require.Equal(t, userID, signedInUser.ID)
	require.NotEmpty(t, tokens.AccessToken)
	_, _, err = auth.LoginVerifyOTP(ctx, login.LoginChallenge, "", "other-device", "replay")
	require.ErrorIs(t, err, ErrOTPInvalid)

	magicToken := "strict-magic-link-under-dev-flags"
	_, err = repo.InsertMagicLink(ctx, auth.IntegrationMagicHash(magicToken), userID, time.Now().Add(time.Minute))
	require.NoError(t, err)
	magicTokens, _, err := auth.CompleteMagicLink(ctx, magicToken, "magic-device", "integration")
	require.NoError(t, err)
	require.NotEmpty(t, magicTokens.AccessToken)
	_, _, err = auth.CompleteMagicLink(ctx, magicToken, "magic-replay", "integration")
	require.Error(t, err, "magic links remain one-time while the development flags are enabled")
}
