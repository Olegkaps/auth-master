package migrate_test

import (
	"context"
	"testing"

	"github.com/olegkapshai/auth-master/internal/migrate"
	"github.com/olegkapshai/auth-master/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestIntegration_OpenAndUp(t *testing.T) {
	ctx := context.Background()
	dsn, done := testutil.StartPostgres16TestcontainerForTest(t, ctx)
	defer done()
	db, err := migrate.Open(dsn)
	require.NoError(t, err)
	require.NoError(t, migrate.Up(db))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	_ = sqlDB.Close()
}
