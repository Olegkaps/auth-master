package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/config"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/olegkapshai/auth-master/internal/migrate"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/olegkapshai/auth-master/internal/testutil"
	"github.com/stretchr/testify/require"
)

// changePwd2FA injects the required password-change OTP and calls ChangePassword.
func changePwd2FA(t *testing.T, a *Auth, repo repository.Repository, ctx context.Context, uid uuid.UUID, oldPwd, newPwd string) error {
	t.Helper()
	code := "918273"
	_, err := repo.CreateEmailOTP(ctx, uid, domain.OTPPasswordChange, a.IntegrationOTPHash(code), time.Now().Add(time.Minute), nil)
	require.NoError(t, err)
	return a.ChangePassword(ctx, uid, oldPwd, newPwd, code)
}

func testDB(t *testing.T) (*repository.Store, func()) {
	t.Helper()
	ctx := context.Background()
	dsn, terminate := testutil.StartPostgres16TestcontainerForTest(t, ctx)
	db, err := migrate.Open(dsn)
	require.NoError(t, err)
	require.NoError(t, migrate.Up(db))
	cleanup := func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
		terminate()
	}
	return repository.New(db), cleanup
}

func testConfig() *config.Config {
	k := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	return &config.Config{
		DatabaseURL:                  "unused",
		PasswordHistoryEncryptionKey: k,
		SigningKeyMasterKey:          k,
		AccessTokenTTL:               time.Minute,
		RefreshTokenTTL:              time.Hour,
		SigningGracePeriod:           time.Minute,
		PasswordMaxAge:               time.Hour * 24 * 365,
		PasswordHistoryN:             5,
		OTPCodeTTL:                   time.Minute,
		OTPCodeLength:                6,
		MaxSessionsPerUser:           10,
		LoginFailWindow:              time.Minute,
		LoginFailMax:                 10,
		LoginLockDuration:            time.Minute,
		NotifyOnFailThreshold:        99,
	}
}

// seedSuperInvite creates a superuser and returns a fresh registration invite token (integration tests).
func seedSuperInvite(t *testing.T, a *Auth, repo repository.Repository, ctx context.Context) string {
	t.Helper()
	aid, err := repo.CreateHumanUser(ctx, "invite-admin", "invadmin@test.dev", "bootstrap-placeholder-hash")
	require.NoError(t, err)
	require.NoError(t, repo.SetSuperuser(ctx, aid, true))
	raw, _, _, err := a.CreateRegistrationInvite(ctx, aid, nil, false, time.Hour)
	require.NoError(t, err)
	return raw
}

func TestIntegration_RegisterAndPasswordPolicy(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	m := &mail.Sender{Host: "localhost", Port: 1025, From: "t@test.dev"}
	a, err := NewAuth(testConfig(), repo, m, nil)
	require.NoError(t, err)
	require.NoError(t, a.EnsureBootstrap(ctx))

	inv := seedSuperInvite(t, a, repo, ctx)
	id, err := a.Register(ctx, inv, "u1", "u1@test.dev", "Password-One1!")
	require.NoError(t, err)
	err = changePwd2FA(t, a, repo, ctx, id, "Password-One1!", "Password-Two2!")
	require.NoError(t, err)
	err = changePwd2FA(t, a, repo, ctx, id, "Password-Two2!", "Password-Two2!")
	require.Error(t, err)
}
