package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/testutil"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestIntegration_MigrateDBRoleNamePreflightAndRepair(t *testing.T) {
	ctx := context.Background()
	dsn, done := testutil.StartPostgres16TestcontainerForTest(t, ctx)
	defer done()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, MigrateDB(db))
	require.NoError(t, db.Exec("DROP INDEX IF EXISTS roles_name_ci_unique").Error)
	require.NoError(t, db.Exec("ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_name_not_blank").Error)

	adminA := uuid.New()
	adminB := uuid.New()
	blank := uuid.New()
	padded := uuid.New()
	for id, name := range map[uuid.UUID]string{
		adminA: " Admin ",
		adminB: "admin",
		blank:  "   ",
		padded: " editors ",
	} {
		require.NoError(t, db.Exec("INSERT INTO roles (id, name, description, created_at, updated_at) VALUES (?, ?, '', NOW(), NOW())", id, name).Error)
	}

	err = MigrateDB(db)
	require.Error(t, err)
	require.Contains(t, err.Error(), "role-name migration blocked")
	require.Contains(t, err.Error(), "blank names")
	require.Contains(t, err.Error(), blank.String())
	require.Contains(t, err.Error(), `name="   "`)
	require.Contains(t, err.Error(), "normalized collisions")
	require.Contains(t, err.Error(), adminA.String())
	require.Contains(t, err.Error(), adminB.String())
	require.Contains(t, err.Error(), `key="admin"`)

	var unchanged []legacyRoleName
	require.NoError(t, db.Raw("SELECT id, name FROM roles WHERE id IN ? ORDER BY id", []uuid.UUID{adminA, adminB, blank, padded}).Scan(&unchanged).Error)
	byID := make(map[uuid.UUID]string, len(unchanged))
	for _, role := range unchanged {
		byID[role.ID] = role.Name
	}
	require.Equal(t, " Admin ", byID[adminA], "failed preflight must not silently normalize an ambiguous key")
	require.Equal(t, "admin", byID[adminB])
	require.Equal(t, "   ", byID[blank])
	require.Equal(t, " editors ", byID[padded], "all trimming waits until the complete preflight succeeds")

	require.NoError(t, db.Exec("UPDATE roles SET name = 'Admin-primary' WHERE id = ?", adminA).Error)
	require.NoError(t, db.Exec("UPDATE roles SET name = 'admin-secondary' WHERE id = ?", adminB).Error)
	require.NoError(t, db.Exec("UPDATE roles SET name = 'viewer' WHERE id = ?", blank).Error)
	require.NoError(t, MigrateDB(db), "the operator can repair the listed rows and rerun safely")

	var trimmed string
	require.NoError(t, db.Raw("SELECT name FROM roles WHERE id = ?", padded).Scan(&trimmed).Error)
	require.Equal(t, "editors", trimmed)
	require.Error(t, db.Exec("INSERT INTO roles (id, name, description, created_at, updated_at) VALUES (?, ' EDITORS ', '', NOW(), NOW())", uuid.New()).Error,
		"raw SQL cannot insert a case/space duplicate after migration")
	require.Error(t, db.Exec("INSERT INTO roles (id, name, description, created_at, updated_at) VALUES (?, '   ', '', NOW(), NOW())", uuid.New()).Error,
		"raw SQL cannot insert a blank role after migration")
}

func TestIntegration_MigrateDBRestoresTokenVersionWithoutDataLoss(t *testing.T) {
	ctx := context.Background()
	dsn, done := testutil.StartPostgres16TestcontainerForTest(t, ctx)
	defer done()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, MigrateDB(db))
	store := New(db)

	activeHumanID, err := store.CreateHumanUser(ctx, "legacy-active-human", "legacy-active-human@test.dev", "hash")
	require.NoError(t, err)
	activeServiceID, err := store.CreateServiceUser(ctx, "legacy-active-service", "hash", false)
	require.NoError(t, err)
	bannedHumanID, err := store.CreateHumanUser(ctx, "legacy-banned-human", "legacy-banned-human@test.dev", "hash")
	require.NoError(t, err)
	bannedServiceID, err := store.CreateServiceUser(ctx, "legacy-banned-service", "hash", false)
	require.NoError(t, err)

	activeHash := []byte("preserved-active-refresh-session")
	_, activeSessionID, err := store.UpsertRefreshSessionForActiveVersion(
		ctx, activeHumanID, 0, "legacy-active-device", "browser", activeHash, time.Now().Add(time.Hour), 10,
	)
	require.NoError(t, err)
	bannedHash := []byte("preserved-banned-refresh-session")
	_, bannedSessionID, err := store.UpsertRefreshSessionForActiveVersion(
		ctx, bannedHumanID, 0, "legacy-banned-device", "browser", bannedHash, time.Now().Add(time.Hour), 10,
	)
	require.NoError(t, err)
	alreadyRevokedHash := []byte("preserved-already-revoked-session")
	_, alreadyRevokedSessionID, err := store.UpsertRefreshSessionForActiveVersion(
		ctx, bannedHumanID, 0, "legacy-already-revoked-device", "browser", alreadyRevokedHash, time.Now().Add(time.Hour), 10,
	)
	require.NoError(t, err)
	require.NoError(t, store.RevokeRefreshSession(ctx, alreadyRevokedSessionID))
	alreadyRevokedBefore, err := store.GetRefreshByID(ctx, alreadyRevokedSessionID)
	require.NoError(t, err)
	require.NotNil(t, alreadyRevokedBefore)
	require.NotNil(t, alreadyRevokedBefore.RevokedAt)
	require.NoError(t, db.Exec("UPDATE users SET banned_at = NOW(), ban_reason = 'legacy incident' WHERE id IN ?", []uuid.UUID{bannedHumanID, bannedServiceID}).Error)
	require.NoError(t, db.Exec("ALTER TABLE users DROP COLUMN token_version").Error)

	// A legacy deployment restarts onto the new binary before AutoMigrate. Close
	// the fixture's pool so prepared plans created against the modern seed schema
	// cannot survive the deliberate DROP/ADD simulation and produce PostgreSQL's
	// "cached plan must not change result type" test artifact.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	store = New(db)
	require.NoError(t, MigrateDB(db))
	assertVersion := func(userID uuid.UUID, want int64) {
		t.Helper()
		user, getErr := store.GetUserByID(ctx, userID)
		require.NoError(t, getErr)
		require.NotNil(t, user)
		require.Equal(t, want, user.TokenVersion)
	}
	assertVersion(activeHumanID, 0)
	assertVersion(activeServiceID, 0)
	assertVersion(bannedHumanID, 1)
	assertVersion(bannedServiceID, 1)

	for _, tc := range []struct {
		id      uuid.UUID
		userID  uuid.UUID
		hash    []byte
		revoked bool
	}{
		{activeSessionID, activeHumanID, activeHash, false},
		{bannedSessionID, bannedHumanID, bannedHash, true},
		{alreadyRevokedSessionID, bannedHumanID, alreadyRevokedHash, true},
	} {
		row, getErr := store.GetRefreshByID(ctx, tc.id)
		require.NoError(t, getErr)
		require.NotNil(t, row)
		require.Equal(t, tc.userID, row.UserID)
		require.Equal(t, tc.hash, row.TokenHash)
		if tc.revoked {
			require.NotNil(t, row.RevokedAt)
		} else {
			require.Nil(t, row.RevokedAt)
		}
	}
	bannedAfterMigration, err := store.GetRefreshByID(ctx, bannedSessionID)
	require.NoError(t, err)
	require.NotNil(t, bannedAfterMigration.RevokedAt)
	migrationRevokedAt := *bannedAfterMigration.RevokedAt
	alreadyRevokedAfter, err := store.GetRefreshByID(ctx, alreadyRevokedSessionID)
	require.NoError(t, err)
	require.Equal(t, *alreadyRevokedBefore.RevokedAt, *alreadyRevokedAfter.RevokedAt,
		"the migration must preserve an existing revocation audit timestamp")

	require.NoError(t, MigrateDB(db), "the token-version repair must be idempotent")
	assertVersion(activeHumanID, 0)
	assertVersion(activeServiceID, 0)
	assertVersion(bannedHumanID, 1)
	assertVersion(bannedServiceID, 1)
	bannedAfterRerun, err := store.GetRefreshByID(ctx, bannedSessionID)
	require.NoError(t, err)
	require.NotNil(t, bannedAfterRerun)
	require.NotNil(t, bannedAfterRerun.RevokedAt)
	require.Equal(t, migrationRevokedAt, *bannedAfterRerun.RevokedAt,
		"an idempotent rerun must not rewrite the migration revocation timestamp")
}
