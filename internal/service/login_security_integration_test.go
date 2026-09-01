package service

import (
	"context"
	"testing"
	"time"

	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/stretchr/testify/require"
)

// A superuser invite grants the registered account superuser access.
func TestIntegration_SuperuserInvite(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{}, nil)
	require.NoError(t, err)

	admin, err := repo.CreateHumanUser(ctx, "inv-super-admin", "isa@test.dev", "h")
	require.NoError(t, err)
	require.NoError(t, repo.SetSuperuser(ctx, admin, true))

	// Regular invite → standard user.
	reg, _, _, err := a.CreateRegistrationInvite(ctx, admin, nil, false, time.Hour)
	require.NoError(t, err)
	uid, err := a.Register(ctx, reg, "plainguy", "plainguy@test.dev", "Plain-Guy-11!")
	require.NoError(t, err)
	su, err := a.IsSuperuser(ctx, uid)
	require.NoError(t, err)
	require.False(t, su)

	// Superuser invite → superuser account.
	sInv, _, _, err := a.CreateRegistrationInvite(ctx, admin, nil, true, time.Hour)
	require.NoError(t, err)
	sid, err := a.Register(ctx, sInv, "superguy", "superguy@test.dev", "Super-Guy-22!")
	require.NoError(t, err)
	su2, err := a.IsSuperuser(ctx, sid)
	require.NoError(t, err)
	require.True(t, su2, "invite with superuser=true must grant superuser")
}

// A wrong login OTP burns the challenge: no second OTP attempt — the user must
// restart from the password step (which mints a fresh challenge + code).
func TestIntegration_WrongOTPBurnsChallenge(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{Host: "localhost", Port: 1025, From: "t@test.dev"}, nil)
	require.NoError(t, err)
	require.NoError(t, a.EnsureBootstrap(ctx))

	inv := seedSuperInvite(t, a, repo, ctx)
	uid, err := a.Register(ctx, inv, "otpuser", "otp@test.dev", "Otp-User-11!")
	require.NoError(t, err)

	res, err := a.LoginPassword(ctx, "otpuser", "Otp-User-11!", nil)
	require.NoError(t, err)
	_, err = repo.CreateEmailOTP(ctx, uid, domain.OTPLogin, a.IntegrationOTPHash("424242"), time.Now().Add(time.Minute), &res.LoginChallenge)
	require.NoError(t, err)

	// Wrong code → invalid.
	_, _, err = a.LoginVerifyOTP(ctx, res.LoginChallenge, "000000", "d", "b")
	require.ErrorIs(t, err, ErrOTPInvalid)

	// The correct code no longer works — the challenge was burned by the wrong try.
	_, _, err = a.LoginVerifyOTP(ctx, res.LoginChallenge, "424242", "d", "b")
	require.ErrorIs(t, err, ErrOTPInvalid)

	// Restarting from the password step yields a fresh challenge that works.
	res2, err := a.LoginPassword(ctx, "otpuser", "Otp-User-11!", nil)
	require.NoError(t, err)
	require.NotEqual(t, res.LoginChallenge, res2.LoginChallenge)
	_, err = repo.CreateEmailOTP(ctx, uid, domain.OTPLogin, a.IntegrationOTPHash("135790"), time.Now().Add(time.Minute), &res2.LoginChallenge)
	require.NoError(t, err)
	tokens, _, err := a.LoginVerifyOTP(ctx, res2.LoginChallenge, "135790", "d", "b")
	require.NoError(t, err)
	require.NotEmpty(t, tokens.AccessToken)
}

func TestIntegration_LoginFailureAliasesShareOneLockCounter(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	cfg := testConfig()
	cfg.LoginFailMax = 3
	cfg.NotifyOnFailThreshold = 2
	mailer := &passwordResetMailer{}
	a, err := NewAuth(cfg, repo, mailer, nil)
	require.NoError(t, err)

	invite := seedSuperInvite(t, a, repo, ctx)
	uid, err := a.Register(ctx, invite, "alias-lock", "Alias.Lock@Example.Test", "Alias-Lock-11!")
	require.NoError(t, err)
	for _, identity := range []string{"alias-lock", "ALIAS.LOCK@EXAMPLE.TEST", "alias-lock"} {
		_, err = a.LoginPassword(ctx, identity, "wrong-password", nil)
		require.ErrorIs(t, err, ErrInvalidCredentials)
	}

	user, err := repo.GetUserByID(ctx, uid)
	require.NoError(t, err)
	require.NotNil(t, user.LockedUntil)
	count, err := repo.CountFailedLogins(ctx, "alias-lock", time.Now().Add(-time.Minute))
	require.NoError(t, err)
	require.EqualValues(t, 3, count)
	require.Equal(t, 1, mailer.calls, "login/email aliases must trigger one shared threshold notification")
	emailCount, err := repo.CountFailedLogins(ctx, "alias.lock@example.test", time.Now().Add(-time.Minute))
	require.NoError(t, err)
	require.Zero(t, emailCount)
	_, err = a.LoginPassword(ctx, "alias.lock@example.test", "Alias-Lock-11!", nil)
	require.ErrorIs(t, err, ErrLocked)
}

// A user can revoke their own session directly (no OTP); the refresh token dies.
func TestIntegration_RevokeOwnSession(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{Host: "localhost", Port: 1025, From: "t@test.dev"}, nil)
	require.NoError(t, err)
	require.NoError(t, a.EnsureBootstrap(ctx))

	inv := seedSuperInvite(t, a, repo, ctx)
	uid, err := a.Register(ctx, inv, "revuser", "rev@test.dev", "Rev-User-11!")
	require.NoError(t, err)

	tokens := loginFull(t, a, repo, ctx, "revuser", "Rev-User-11!", "browser-X")
	sessions, err := repo.ListRefreshSessions(ctx, uid)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	sid := sessions[0].ID

	// Revoking someone else's session is rejected.
	other, err := repo.CreateHumanUser(ctx, "rev-other", "revother@test.dev", "h")
	require.NoError(t, err)
	require.ErrorIs(t, a.RevokeOwnSession(ctx, other, sid), ErrNotFound)

	// Own session revokes directly; the refresh token stops working.
	require.NoError(t, a.RevokeOwnSession(ctx, uid, sid))
	_, err = a.Refresh(ctx, tokens.RefreshToken, "browser-X", "b")
	require.Error(t, err)
}
