package service

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/stretchr/testify/require"
)

// loginFull runs the full password→OTP flow and returns the issued token pair.
func loginFull(t *testing.T, a *Auth, repo repository.Repository, ctx context.Context, login, password, device string) *TokenPair {
	t.Helper()
	res, err := a.LoginPassword(ctx, login, password, nil)
	require.NoError(t, err)
	require.True(t, res.OTPRequired)
	code := "424242"
	uu, err := repo.GetUserByLogin(ctx, login)
	require.NoError(t, err)
	_, err = repo.CreateEmailOTP(ctx, uu.ID, domain.OTPLogin, a.IntegrationOTPHash(code), time.Now().Add(time.Minute), &res.LoginChallenge)
	require.NoError(t, err)
	tokens, _, err := a.LoginVerifyOTP(ctx, res.LoginChallenge, code, device, "browser")
	require.NoError(t, err)
	return tokens
}

// Re-logging into the same account from the same device replaces the session:
// only the last one stays active, and the previous refresh token stops working.
func TestIntegration_ReloginSameDeviceKeepsLastSession(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{Host: "localhost", Port: 1025, From: "t@test.dev"}, nil)
	require.NoError(t, err)
	require.NoError(t, a.EnsureBootstrap(ctx))

	inv := seedSuperInvite(t, a, repo, ctx)
	uid, err := a.Register(ctx, inv, "dev1user", "dev1@test.dev", "Dev1-Pass-99!")
	require.NoError(t, err)

	first := loginFull(t, a, repo, ctx, "dev1user", "Dev1-Pass-99!", "browser-A")
	second := loginFull(t, a, repo, ctx, "dev1user", "Dev1-Pass-99!", "browser-A")

	// Only one active session exists for device browser-A.
	sessions, err := repo.ListRefreshSessions(ctx, uid)
	require.NoError(t, err)
	active := 0
	for _, s := range sessions {
		if s.DeviceID == "browser-A" && s.RevokedAt == nil && time.Now().Before(s.ExpiresAt) {
			active++
		}
	}
	require.Equal(t, 1, active, "same device must keep exactly one active session")

	// The first (replaced) refresh token no longer works; the latest one does.
	_, err = a.Refresh(ctx, first.RefreshToken, "browser-A", "browser")
	require.Error(t, err)
	_, err = a.Refresh(ctx, second.RefreshToken, "browser-A", "browser")
	require.NoError(t, err)

	// A different device is an independent session (two active in total).
	loginFull(t, a, repo, ctx, "dev1user", "Dev1-Pass-99!", "browser-B")
	sessions, err = repo.ListRefreshSessions(ctx, uid)
	require.NoError(t, err)
	activeAll := 0
	for _, s := range sessions {
		if s.RevokedAt == nil && time.Now().Before(s.ExpiresAt) {
			activeAll++
		}
	}
	require.Equal(t, 2, activeAll, "distinct devices keep distinct sessions")
}

// Every one-time credential is rejected once expired.
func TestIntegration_ExpiredCredentialsRejected(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{Host: "localhost", Port: 1025, From: "t@test.dev"}, nil)
	require.NoError(t, err)
	require.NoError(t, a.EnsureBootstrap(ctx))

	inv := seedSuperInvite(t, a, repo, ctx)
	uid, err := a.Register(ctx, inv, "expuser", "exp@test.dev", "Exp-Pass-77!")
	require.NoError(t, err)
	past := time.Now().Add(-time.Minute)

	// Expired login OTP (bound to a challenge) → rejected.
	challenge := "exp-challenge"
	_, err = repo.CreateEmailOTP(ctx, uid, domain.OTPLogin, a.IntegrationOTPHash("111111"), past, &challenge)
	require.NoError(t, err)
	_, _, err = a.LoginVerifyOTP(ctx, challenge, "111111", "d", "b")
	require.ErrorIs(t, err, ErrOTPInvalid)

	// Expired password-reset OTP → rejected.
	_, err = repo.CreateEmailOTP(ctx, uid, domain.OTPPasswordChange, a.IntegrationOTPHash("222222"), past, nil)
	require.NoError(t, err)
	require.ErrorIs(t, a.ResetPasswordWithOTP(ctx, "expuser", "222222", "New-Exp-Pass-88!"), ErrOTPInvalid)

	// Expired magic link → rejected.
	token := hex.EncodeToString([]byte("expired-magic-token-0123456789ab"))
	_, err = repo.InsertMagicLink(ctx, a.IntegrationMagicHash(token), uid, past)
	require.NoError(t, err)
	_, _, err = a.CompleteMagicLink(ctx, token, "d", "b")
	require.ErrorIs(t, err, ErrOTPInvalid)

	// Expired registration invite → rejected.
	invTok := hex.EncodeToString([]byte("expired-invite-token-0123456789a"))
	locked := "invitee@test.dev"
	_, err = repo.InsertRegistrationInvite(ctx, a.IntegrationMagicHash(invTok), &locked, false, past, uid)
	require.NoError(t, err)
	_, err = a.Register(ctx, invTok, "invitee", "invitee@test.dev", "Invitee-Pass-99!")
	require.ErrorIs(t, err, ErrInvalidInvite)
}
