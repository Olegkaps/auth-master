package service

import (
	"context"
	"testing"

	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/stretchr/testify/require"
)

// Exercises the password-history checks end-to-end: exact reuse and
// near-duplicate (small edit distance) passwords must both be rejected.
func TestIntegration_PasswordHistoryRejectsReuseAndSimilar(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	m := &mail.Sender{Host: "localhost", Port: 1025, From: "t@test.dev"}
	a, err := NewAuth(testConfig(), repo, m, nil)
	require.NoError(t, err)
	require.NoError(t, a.EnsureBootstrap(ctx))

	inv := seedSuperInvite(t, a, repo, ctx)
	uid, err := a.Register(ctx, inv, "histuser", "hist@test.dev", "Alpha-One-11!")
	require.NoError(t, err)

	// Reusing the current password is rejected as "password reused".
	err = changePwd2FA(t, a, repo, ctx, uid, "Alpha-One-11!", "Alpha-One-11!")
	require.ErrorIs(t, err, ErrPasswordPolicy)

	// A distinct, complex password is accepted.
	require.NoError(t, changePwd2FA(t, a, repo, ctx, uid, "Alpha-One-11!", "Bravo-Two-22!"))

	// A near-duplicate of a historical password (edit distance <= 2) is rejected.
	err = changePwd2FA(t, a, repo, ctx, uid, "Bravo-Two-22!", "Bravo-Two-23!")
	require.ErrorIs(t, err, ErrPasswordPolicy)

	// Reusing the very first password (still within history window) is rejected.
	err = changePwd2FA(t, a, repo, ctx, uid, "Bravo-Two-22!", "Alpha-One-11!")
	require.ErrorIs(t, err, ErrPasswordPolicy)

	// A sufficiently different password is accepted.
	require.NoError(t, changePwd2FA(t, a, repo, ctx, uid, "Bravo-Two-22!", "Charlie-9x-Zed!"))
}
