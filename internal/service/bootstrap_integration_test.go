package service

import (
	"context"
	"testing"

	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/stretchr/testify/require"
)

func TestIntegration_EnsureBootstrapAdmin(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()

	cfg := testConfig()
	cfg.BootstrapSuperuserLogin = "bootadm"
	cfg.BootstrapSuperuserEmail = "bootadm@test.dev"
	cfg.BootstrapSuperuserPassword = "Password-Bootstrap-1!"

	m := &mail.Sender{Host: "127.0.0.1", Port: 1025, From: "t@test.dev"}
	a, err := NewAuth(cfg, repo, m, nil)
	require.NoError(t, err)
	require.NoError(t, a.EnsureBootstrap(ctx))
	require.NoError(t, a.EnsureBootstrapAdmin(ctx))

	n, err := repo.CountHumanUsers(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	u, err := repo.GetUserByLogin(ctx, "bootadm")
	require.NoError(t, err)
	require.NotNil(t, u)
	require.True(t, u.Superuser)

	require.NoError(t, a.EnsureBootstrapAdmin(ctx))
	n2, err := repo.CountHumanUsers(ctx)
	require.NoError(t, err)
	require.Equal(t, n, n2)
}
