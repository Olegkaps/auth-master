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

func TestIntegration_LoginOTPAndRefresh(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	m := &mail.Sender{Host: "localhost", Port: 1025, From: "t@test.dev"}
	a, err := NewAuth(testConfig(), repo, m, nil)
	require.NoError(t, err)
	require.NoError(t, a.EnsureBootstrap(ctx))

	inv := seedSuperInvite(t, a, repo, ctx)
	uid, err := a.Register(ctx, inv, "flow", "flow@test.dev", "secret-pass-1")
	require.NoError(t, err)

	_, err = a.LoginPassword(ctx, "flow", "wrong", nil)
	require.Error(t, err)

	res, err := a.LoginPassword(ctx, "flow", "secret-pass-1", nil)
	require.NoError(t, err)
	require.True(t, res.OTPRequired)

	code := "424242"
	chash := hashOTP(a.otpPepper, code)
	_, err = repo.CreateEmailOTP(ctx, uid, domain.OTPLogin, chash, time.Now().Add(time.Minute), nil)
	require.NoError(t, err)

	tokens, u, err := a.LoginVerifyOTP(ctx, "flow", code, "device-a", "phone")
	require.NoError(t, err)
	require.NotNil(t, tokens)
	require.NotNil(t, u)

	tokens2, err := a.Refresh(ctx, tokens.RefreshToken, "device-a", "phone")
	require.NoError(t, err)
	require.NotEmpty(t, tokens2.AccessToken)

	require.NoError(t, a.Logout(ctx, tokens2.RefreshToken))

	_, err = a.VerifyAccessToken(ctx, tokens.AccessToken, jwtutil.TypeService)
	require.Error(t, err)

	claims, err := a.VerifyAccessToken(ctx, tokens.AccessToken, jwtutil.TypeAccess)
	require.NoError(t, err)
	require.Equal(t, "flow", claims.Login)
}
