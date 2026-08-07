package repository

import (
	"context"
	"testing"

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
