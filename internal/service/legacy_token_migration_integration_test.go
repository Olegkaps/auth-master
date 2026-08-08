package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/jwtutil"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/olegkapshai/auth-master/internal/testutil"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func signLegacyTokenWithoutVersion(t *testing.T, secret []byte, kid string, userID uuid.UUID, login, typ string) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   userID.String(),
		"login": login,
		"typ":   typ,
		"kid":   kid,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	require.NoError(t, err)
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	require.NoError(t, err)
	_, hasVersion := parsed.Claims.(jwt.MapClaims)["token_version"]
	require.False(t, hasVersion, "fixture must represent a JWT issued before token_version existed")
	return token
}

func TestIntegration_LegacyBannedTokensCannotResurrectAfterMigrationAndUnban(t *testing.T) {
	ctx := context.Background()
	dsn, done := testutil.StartPostgres16TestcontainerForTest(t, ctx)
	defer done()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, repository.MigrateDB(db))
	repo := repository.New(db)
	auth, err := NewAuth(testConfig(), repo, &mail.Sender{}, nil)
	require.NoError(t, err)
	require.NoError(t, auth.EnsureBootstrap(ctx))
	kid, secret, err := auth.currentSigningSecret(ctx)
	require.NoError(t, err)

	activeID, err := repo.CreateHumanUser(ctx, "legacy-token-active", "legacy-token-active@test.dev", "hash")
	require.NoError(t, err)
	humanID, err := repo.CreateHumanUser(ctx, "legacy-token-banned-human", "legacy-token-banned-human@test.dev", "hash")
	require.NoError(t, err)
	serviceID, err := repo.CreateServiceUser(ctx, "legacy-token-banned-service", "hash")
	require.NoError(t, err)
	activeToken := signLegacyTokenWithoutVersion(t, secret, kid, activeID, "legacy-token-active", jwtutil.TypeAccess)
	humanToken := signLegacyTokenWithoutVersion(t, secret, kid, humanID, "legacy-token-banned-human", jwtutil.TypeAccess)
	serviceToken := signLegacyTokenWithoutVersion(t, secret, kid, serviceID, "legacy-token-banned-service", jwtutil.TypeService)
	activeRefreshToken := "legacy-active-opaque-refresh-token"
	bannedRefreshToken := "legacy-banned-opaque-refresh-token"
	activeRefreshHash := hashRefreshToken(activeRefreshToken)
	bannedRefreshHash := hashRefreshToken(bannedRefreshToken)
	_, activeSessionID, err := repo.UpsertRefreshSessionForActiveVersion(
		ctx, activeID, 0, "legacy-active-device", "browser", activeRefreshHash, time.Now().Add(time.Hour), 10,
	)
	require.NoError(t, err)
	_, bannedSessionID, err := repo.UpsertRefreshSessionForActiveVersion(
		ctx, humanID, 0, "legacy-banned-device", "browser", bannedRefreshHash, time.Now().Add(time.Hour), 10,
	)
	require.NoError(t, err)

	require.NoError(t, db.Exec("UPDATE users SET banned_at = NOW(), ban_reason = 'legacy incident' WHERE id IN ?", []uuid.UUID{humanID, serviceID}).Error)
	require.NoError(t, db.Exec("ALTER TABLE users DROP COLUMN token_version").Error)
	// Production runs the migration after starting a new process. Reopen the
	// fixture pool at that boundary so statements prepared while seeding the
	// modern schema cannot retain the deliberately dropped column's row shape.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, repository.MigrateDB(db))
	repo = repository.New(db)
	auth, err = NewAuth(testConfig(), repo, &mail.Sender{}, nil)
	require.NoError(t, err)

	active, err := repo.GetUserByID(ctx, activeID)
	require.NoError(t, err)
	require.Zero(t, active.TokenVersion, "active legacy users retain compatibility with versionless tokens")
	_, err = auth.VerifyAccessToken(ctx, activeToken, jwtutil.TypeAccess)
	require.NoError(t, err)
	activeSession, err := repo.GetRefreshByID(ctx, activeSessionID)
	require.NoError(t, err)
	require.NotNil(t, activeSession)
	require.Equal(t, activeRefreshHash, activeSession.TokenHash)
	require.Nil(t, activeSession.RevokedAt)
	bannedSession, err := repo.GetRefreshByID(ctx, bannedSessionID)
	require.NoError(t, err)
	require.NotNil(t, bannedSession)
	require.Equal(t, bannedRefreshHash, bannedSession.TokenHash)
	require.NotNil(t, bannedSession.RevokedAt)
	bannedRevokedAt := *bannedSession.RevokedAt

	for _, userID := range []uuid.UUID{humanID, serviceID} {
		user, getErr := repo.GetUserByID(ctx, userID)
		require.NoError(t, getErr)
		require.EqualValues(t, 1, user.TokenVersion)
		require.NoError(t, repo.SetUserBan(ctx, userID, nil, ""))
	}
	_, err = auth.VerifyAccessToken(ctx, humanToken, jwtutil.TypeAccess)
	require.ErrorIs(t, err, ErrInvalidCredentials, "unban must not resurrect a versionless human access token")
	_, err = auth.VerifyAccessToken(ctx, serviceToken, jwtutil.TypeService)
	require.ErrorIs(t, err, ErrInvalidCredentials, "unban must not resurrect a versionless service token")
	_, err = auth.Refresh(ctx, bannedRefreshToken, "legacy-banned-device", "browser")
	require.ErrorIs(t, err, ErrInvalidCredentials, "unban must not resurrect an opaque refresh token from before the legacy ban migration")
	bannedSessionAfter, err := repo.GetRefreshByID(ctx, bannedSessionID)
	require.NoError(t, err)
	require.NotNil(t, bannedSessionAfter)
	require.Equal(t, bannedRefreshHash, bannedSessionAfter.TokenHash)
	require.Equal(t, bannedRevokedAt, *bannedSessionAfter.RevokedAt)

	rotated, err := auth.Refresh(ctx, activeRefreshToken, "legacy-active-device", "browser")
	require.NoError(t, err, "an active legacy user's opaque refresh token remains compatible")
	require.NotEmpty(t, rotated.RefreshToken)
	activeSessionAfter, err := repo.GetRefreshByID(ctx, activeSessionID)
	require.NoError(t, err)
	require.NotNil(t, activeSessionAfter)
	require.Equal(t, activeSessionID, activeSessionAfter.ID)
	require.Equal(t, hashRefreshToken(rotated.RefreshToken), activeSessionAfter.TokenHash)
	require.Nil(t, activeSessionAfter.RevokedAt)
}
