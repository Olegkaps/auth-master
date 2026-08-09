package service

import (
	"context"
	"testing"

	"github.com/olegkapshai/auth-master/internal/crypto"
	"github.com/olegkapshai/auth-master/internal/domain"
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

func TestIntegrationEnsureBootstrapSuperuserService(t *testing.T) {
	t.Run("creates and reconciles", func(t *testing.T) {
		repo, done := testDB(t)
		defer done()
		cfg := testConfig()
		cfg.BootstrapSuperuserServiceLogin = "Demo-Seeder"
		cfg.BootstrapSuperuserServiceSecret = "Demo-Service-Secret1!"
		a, err := NewAuth(cfg, repo, &mail.Sender{Host: "127.0.0.1", Port: 1025, From: "t@test.dev"}, nil)
		require.NoError(t, err)
		require.NoError(t, a.EnsureBootstrapSuperuserService(t.Context()))
		require.NoError(t, a.EnsureBootstrapSuperuserService(t.Context()))
		user, err := repo.GetUserByLogin(t.Context(), "demo-seeder")
		require.NoError(t, err)
		require.NotNil(t, user)
		require.Equal(t, domain.UserService, user.Kind)
		require.True(t, user.Superuser)
		require.NotNil(t, user.ServiceSecretHash)
		matches, err := crypto.VerifySecret(cfg.BootstrapSuperuserServiceSecret, *user.ServiceSecretHash)
		require.NoError(t, err)
		require.True(t, matches)
	})

	for _, test := range []struct {
		name        string
		secret      string
		superuser   bool
		configured  string
		wantMessage string
	}{
		{name: "secret mismatch", secret: "Original-Service-Secret1!", superuser: true, configured: "Changed-Service-Secret1!", wantMessage: "credentials do not match"},
		{name: "non-superuser collision", secret: "Demo-Service-Secret1!", superuser: false, configured: "Demo-Service-Secret1!", wantMessage: "incompatible account"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo, done := testDB(t)
			defer done()
			hash, err := crypto.HashSecret(test.secret)
			require.NoError(t, err)
			_, err = repo.CreateServiceUser(t.Context(), "demo-seeder", hash, test.superuser)
			require.NoError(t, err)
			cfg := testConfig()
			cfg.BootstrapSuperuserServiceLogin = "demo-seeder"
			cfg.BootstrapSuperuserServiceSecret = test.configured
			a, err := NewAuth(cfg, repo, &mail.Sender{Host: "127.0.0.1", Port: 1025, From: "t@test.dev"}, nil)
			require.NoError(t, err)
			err = a.EnsureBootstrapSuperuserService(t.Context())
			require.ErrorContains(t, err, test.wantMessage)
		})
	}
}
