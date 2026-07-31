package service

import (
	"context"
	"testing"
	"time"

	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/stretchr/testify/require"
)

func TestIntegration_PasswordResetWithOTP(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	m := &mail.Sender{Host: "localhost", Port: 1025, From: "t@test.dev"}
	a, err := NewAuth(testConfig(), repo, m, nil)
	require.NoError(t, err)
	require.NoError(t, a.EnsureBootstrap(ctx))

	inv := seedSuperInvite(t, a, repo, ctx)
	uid, err := a.Register(ctx, inv, "resetme", "reset@test.dev", "Old-Pass-1234!")
	require.NoError(t, err)

	// Unknown login is a silent no-op (no enumeration, no error).
	require.NoError(t, a.StartPasswordReset(ctx, "does-not-exist"))

	// Inject a known OTP for the reset purpose, as the tests do for login.
	code := "135790"
	chash := hashOTP(a.otpPepper, code)
	_, err = repo.CreateEmailOTP(ctx, uid, domain.OTPPasswordChange, chash, time.Now().Add(time.Minute), nil)
	require.NoError(t, err)

	// Wrong code is rejected.
	require.ErrorIs(t, a.ResetPasswordWithOTP(ctx, "resetme", "000000", "New-Pass-5678!"), ErrOTPInvalid)

	// Correct code sets the new password.
	require.NoError(t, a.ResetPasswordWithOTP(ctx, "resetme", code, "New-Pass-5678!"))

	// Old password no longer works; new one does (and requires OTP as usual).
	_, err = a.LoginPassword(ctx, "resetme", "Old-Pass-1234!", nil)
	require.ErrorIs(t, err, ErrInvalidCredentials)

	res, err := a.LoginPassword(ctx, "resetme", "New-Pass-5678!", nil)
	require.NoError(t, err)
	require.True(t, res.OTPRequired)

	// The reset OTP is single-use — replaying it fails.
	require.ErrorIs(t, a.ResetPasswordWithOTP(ctx, "resetme", code, "Another-Pass-9012!"), ErrOTPInvalid)
}
