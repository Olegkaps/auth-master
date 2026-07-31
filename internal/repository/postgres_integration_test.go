package repository

import (
	"context"
	"testing"
	"time"

	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/testutil"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupRepo(t *testing.T) (*Store, func()) {
	t.Helper()
	ctx := context.Background()
	dsn, terminate := testutil.StartPostgres16TestcontainerForTest(t, ctx)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, MigrateDB(db))
	cleanup := func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
		terminate()
	}
	return New(db), cleanup
}

func TestIntegration_UserAndSession(t *testing.T) {
	s, cleanup := setupRepo(t)
	defer cleanup()
	ctx := context.Background()

	id, err := s.CreateHumanUser(ctx, "alice", "a@test.dev", "hash")
	require.NoError(t, err)

	u, err := s.GetUserByLogin(ctx, "alice")
	require.NoError(t, err)
	require.NotNil(t, u)
	require.Equal(t, "human", string(u.Kind))

	th := []byte{1, 2, 3}
	exp := time.Now().Add(time.Hour)
	_, err = s.UpsertRefreshSession(ctx, id, "dev1", "laptop", th, exp)
	require.NoError(t, err)

	row, err := s.FindRefreshByTokenHash(ctx, th)
	require.NoError(t, err)
	require.NotNil(t, row)

	nh := []byte{9, 9, 9}
	require.NoError(t, s.ReplaceRefreshToken(ctx, row.ID, th, nh, exp.Add(time.Hour)))
}

func TestIntegration_SigningKey(t *testing.T) {
	s, cleanup := setupRepo(t)
	defer cleanup()
	ctx := context.Background()
	require.NoError(t, s.InsertSigningKey(ctx, "k1", []byte("c"), []byte("n"), false))
	m, err := s.GetSigningKeyMaterial(ctx, "k1")
	require.NoError(t, err)
	require.NotNil(t, m)
	require.Equal(t, "k1", m.Kid)
}

func TestIntegration_RoleAssignment(t *testing.T) {
	s, cleanup := setupRepo(t)
	defer cleanup()
	ctx := context.Background()
	uid, err := s.CreateHumanUser(ctx, "bob", "b@test.dev", "h")
	require.NoError(t, err)
	rid, err := s.CreateRole(ctx, "editors", "desc", nil)
	require.NoError(t, err)
	require.NoError(t, s.AssignUserRole(ctx, uid, rid, domain.RoleMember, &uid, time.Now(), nil))
	ok, err := s.UserHasRoleName(ctx, uid, "editors", time.Now())
	require.NoError(t, err)
	require.True(t, ok)
}
