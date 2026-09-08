package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/stretchr/testify/require"
)

type acceptedResetMailCancelMailer struct {
	cancel context.CancelFunc
	code   string
}

func (m *acceptedResetMailCancelMailer) Send(_ context.Context, _ []string, subject, body string) error {
	if subject == "Reset your password" {
		m.code = strings.TrimSpace(strings.TrimPrefix(body, "Code:"))
		m.cancel()
	}
	return nil
}

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
	_, issued, err := repo.IssuePasswordResetOTP(ctx, uid, chash, time.Now(), time.Now().Add(time.Minute), 0)
	require.NoError(t, err)
	require.True(t, issued)

	// A wrong code is rejected and counted without evaluating password policy.
	require.ErrorIs(t, a.ResetPasswordWithOTP(ctx, "resetme", "000000", "weak"), ErrOTPInvalid)
	otp, err := repo.GetMostRecentOTP(ctx, uid, domain.OTPPasswordReset)
	require.NoError(t, err)
	require.Equal(t, 1, otp.AttemptCount)
	require.Nil(t, otp.ConsumedAt)

	// Policy failures roll the completion transaction back, so the same correct
	// code remains usable for a fixed password without another email round trip.
	require.ErrorIs(t, a.ResetPasswordWithOTP(ctx, "resetme", code, "weak"), ErrPasswordPolicy)
	require.ErrorIs(t, a.ResetPasswordWithOTP(ctx, "resetme", code, "Old-Pass-1234!"), ErrPasswordPolicy)
	otp, err = repo.GetMostRecentOTP(ctx, uid, domain.OTPPasswordReset)
	require.NoError(t, err)
	require.Nil(t, otp.ConsumedAt)
	originalKey := a.cfg.PasswordHistoryEncryptionKey
	a.cfg.PasswordHistoryEncryptionKey = "invalid-key"
	require.Error(t, a.ResetPasswordWithOTP(ctx, "resetme", code, "New-Pass-5678!"))
	a.cfg.PasswordHistoryEncryptionKey = originalKey
	otp, err = repo.GetMostRecentOTP(ctx, uid, domain.OTPPasswordReset)
	require.NoError(t, err)
	require.Nil(t, otp.ConsumedAt, "crypto preparation errors must leave the correct OTP reusable")

	// Correct code plus valid mutation commits password, history, and consumption.
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

func TestIntegration_PasswordResetStartIsEnumerationSafeAndLeavesFailedDeliveryInactive(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{Host: "127.0.0.1", Port: 1, From: "t@test.dev"}, nil)
	require.NoError(t, err)
	uid, err := repo.CreatePasswordlessHuman(ctx, "no-delivery", "no-delivery@example.test")
	require.NoError(t, err)

	require.NoError(t, a.StartPasswordReset(ctx, "NO-DELIVERY@example.test"), "SMTP failure must not distinguish a real account")
	require.NoError(t, a.Shutdown(ctx), "drain the private delivery worker before inspecting persistence")
	reserved, err := repo.GetMostRecentOTP(ctx, uid, domain.OTPPasswordReset)
	require.NoError(t, err)
	require.NotNil(t, reserved)
	require.Nil(t, reserved.ConsumedAt)
	require.Equal(t, "pending", reserved.DeliveryState, "an undelivered reset credential must remain unusable")
	require.NoError(t, a.StartPasswordReset(ctx, "unknown@example.test"), "unknown accounts have the same result")
}

func TestIntegration_FailedResetDeliveryKeepsPreviouslyDeliveredCodeUsable(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{Host: "127.0.0.1", Port: 1, From: "t@test.dev"}, nil)
	require.NoError(t, err)
	uid, err := repo.CreateHumanUser(ctx, "delivery-preserve", "delivery-preserve@example.test", "old-hash")
	require.NoError(t, err)
	const previousCode = "174296"
	_, issued, err := repo.IssuePasswordResetOTP(ctx, uid, a.IntegrationOTPHash(previousCode), time.Now(), time.Now().Add(time.Minute), 0)
	require.NoError(t, err)
	require.True(t, issued)
	require.NoError(t, a.StartPasswordReset(ctx, "delivery-preserve"), "SMTP failure remains enumeration-safe")
	require.NoError(t, a.Shutdown(ctx), "drain the private delivery worker before using the previous credential")
	require.NoError(t, a.ResetPasswordWithOTP(ctx, "delivery-preserve", previousCode, "Delivery-New9!"), "the previously delivered active code must survive")
	user, err := repo.GetUserByID(ctx, uid)
	require.NoError(t, err)
	require.NotEqual(t, "old-hash", *user.PasswordHash)
}

func TestIntegration_AcceptedResetMailRemainsUsableWhenMailJobContextIsCanceled(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx, cancel := context.WithCancel(context.Background())
	mailer := &acceptedResetMailCancelMailer{cancel: cancel}
	a, err := NewAuth(testConfig(), repo, mailer, nil)
	require.NoError(t, err)
	_, err = repo.CreatePasswordlessHuman(context.Background(), "deadline-reset", "deadline-reset@example.test")
	require.NoError(t, err)

	a.processPasswordReset(ctx, "deadline-reset")
	require.NotEmpty(t, mailer.code, "SMTP accepted a concrete reset code before canceling the job context")
	require.NoError(t, a.ResetPasswordWithOTP(context.Background(), "deadline-reset", mailer.code, "Deadline-Reset9!"),
		"activation must commit on its detached bound after SMTP acceptance")

	result, err := a.LoginPassword(context.Background(), "deadline-reset", "Deadline-Reset9!", nil)
	require.NoError(t, err)
	require.True(t, result.OTPRequired)
}
