package repository

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/testutil"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestIntegration_HumanLoginEmailNamespaceIsAtomic(t *testing.T) {
	ctx := context.Background()
	dsn, done := testutil.StartPostgres16TestcontainerForTest(t, ctx)
	defer done()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, MigrateDB(db))
	store := New(db)
	require.Error(t, db.Exec("INSERT INTO users (id, login, email, kind, password_hash, created_at, updated_at) VALUES (?, 'blank-email', '   ', 'human', 'hash', NOW(), NOW())", uuid.New()).Error)
	validID, err := store.CreateHumanUser(ctx, "valid-email", "valid-email@example.test", "hash")
	require.NoError(t, err)
	require.Error(t, db.Exec("UPDATE users SET email = NULL WHERE id = ?", validID).Error)

	for _, tc := range []struct {
		name   string
		first  [2]string
		second [2]string
	}{
		{name: "login races email", first: [2]string{"shared-a", "owner-a@example.test"}, second: [2]string{"other-a", "SHARED-A"}},
		{name: "email races login", first: [2]string{"other-b", "Shared-B"}, second: [2]string{"SHARED-B", "owner-b@example.test"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := make(chan struct{})
			errs := make(chan error, 2)
			var wg sync.WaitGroup
			for _, identity := range [][2]string{tc.first, tc.second} {
				identity := identity
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					_, createErr := store.CreateHumanUser(ctx, identity[0], identity[1], "hash")
					errs <- createErr
				}()
			}
			close(start)
			wg.Wait()
			close(errs)
			successes := 0
			for createErr := range errs {
				if createErr == nil {
					successes++
				}
			}
			require.Equal(t, 1, successes, "the shared normalized identity must be claimed exactly once")
		})
	}

	t.Run("concurrent updates claim one cross-field key", func(t *testing.T) {
		left, createErr := store.CreateHumanUser(ctx, "update-left", "update-left@example.test", "hash")
		require.NoError(t, createErr)
		right, createErr := store.CreateHumanUser(ctx, "update-right", "update-right@example.test", "hash")
		require.NoError(t, createErr)
		start := make(chan struct{})
		errs := make(chan error, 2)
		var wg sync.WaitGroup
		for _, update := range []func() error{
			func() error { return db.Exec("UPDATE users SET login = 'update-shared' WHERE id = ?", left).Error },
			func() error { return db.Exec("UPDATE users SET email = ' UPDATE-SHARED ' WHERE id = ?", right).Error },
		} {
			update := update
			wg.Add(1)
			go func() { defer wg.Done(); <-start; errs <- update() }()
		}
		close(start)
		wg.Wait()
		close(errs)
		successes := 0
		for updateErr := range errs {
			if updateErr == nil {
				successes++
			}
		}
		require.Equal(t, 1, successes)
	})
}

func TestIntegration_MigrateDBRejectsLegacyCrossFieldIdentityCollision(t *testing.T) {
	ctx := context.Background()
	dsn, done := testutil.StartPostgres16TestcontainerForTest(t, ctx)
	defer done()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, MigrateDB(db))
	require.NoError(t, db.Exec("DROP TRIGGER users_sync_human_identity_keys ON users; DROP TRIGGER users_canonicalize_identity ON users; DROP TABLE user_identity_keys").Error)

	first, second := uuid.New(), uuid.New()
	require.NoError(t, db.Exec("INSERT INTO users (id, login, email, kind, password_hash, created_at, updated_at) VALUES (?, ' Alice ', 'owner@example.test', 'human', 'hash', NOW(), NOW())", first).Error)
	require.NoError(t, db.Exec("INSERT INTO users (id, login, email, kind, password_hash, created_at, updated_at) VALUES (?, 'other', 'ALICE', 'human', 'hash', NOW(), NOW())", second).Error)
	err = MigrateDB(db)
	require.ErrorContains(t, err, "user identity migration blocked")
	require.ErrorContains(t, err, "human:alice")
	var unchanged string
	require.NoError(t, db.Raw("SELECT login FROM users WHERE id = ?", first).Scan(&unchanged).Error)
	require.Equal(t, " Alice ", unchanged)
}

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
