package repository

import (
	"context"
	"errors"
	"fmt"
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

func TestIntegration_RefreshSessionMutationsSerializeWithBan(t *testing.T) {
	ctx := context.Background()
	dsn, done := testutil.StartPostgres16TestcontainerForTest(t, ctx)
	defer done()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, MigrateDB(db))
	store := New(db)
	adminID, err := store.CreateHumanUser(ctx, "session-race-admin", "session-race-admin@test.dev", "hash")
	require.NoError(t, err)

	newUser := func(t *testing.T, suffix string) uuid.UUID {
		t.Helper()
		id, createErr := store.CreateHumanUser(ctx, "session-race-"+suffix, suffix+"@test.dev", "hash")
		require.NoError(t, createErr)
		return id
	}
	expiresAt := time.Now().Add(time.Hour)

	t.Run("issuance commits before ban and the new session is revoked", func(t *testing.T) {
		userID := newUser(t, "issue-first")
		locked := make(chan struct{})
		release := make(chan struct{})
		issueResult := make(chan error, 1)
		go func() {
			_, _, issueErr := store.upsertRefreshSessionForActiveVersion(
				ctx, userID, 0, "device", "browser", []byte("issued-first"), expiresAt, 10,
				func() { close(locked); <-release },
			)
			issueResult <- issueErr
		}()
		<-locked

		banStarted := make(chan struct{})
		banResult := make(chan error, 1)
		go func() {
			close(banStarted)
			banResult <- store.SetUserBan(ctx, userID, &adminID, "incident")
		}()
		<-banStarted
		close(release)
		require.NoError(t, <-issueResult)
		require.NoError(t, <-banResult)

		row, err := store.GetRefreshByUserDevice(ctx, userID, "device")
		require.NoError(t, err)
		require.NotNil(t, row)
		require.NotNil(t, row.RevokedAt)
	})

	t.Run("ban commits before issuance and issuance cannot mutate", func(t *testing.T) {
		userID := newUser(t, "ban-first-issue")
		locked := make(chan struct{})
		release := make(chan struct{})
		banResult := make(chan error, 1)
		go func() {
			banResult <- store.setUserBan(ctx, userID, &adminID, "incident", func() { close(locked); <-release })
		}()
		<-locked

		issueStarted := make(chan struct{})
		issueResult := make(chan error, 1)
		go func() {
			close(issueStarted)
			_, _, issueErr := store.UpsertRefreshSessionForActiveVersion(ctx, userID, 0, "device", "browser", []byte("must-not-write"), expiresAt, 10)
			issueResult <- issueErr
		}()
		<-issueStarted
		close(release)
		require.NoError(t, <-banResult)
		require.ErrorIs(t, <-issueResult, ErrUserInactive)

		row, err := store.GetRefreshByUserDevice(ctx, userID, "device")
		require.NoError(t, err)
		require.Nil(t, row)
	})

	t.Run("unban cannot revive a same-device session using a stale version", func(t *testing.T) {
		userID := newUser(t, "stale-unban")
		originalHash := []byte("original")
		_, _, err := store.UpsertRefreshSessionForActiveVersion(ctx, userID, 0, "device", "browser", originalHash, expiresAt, 10)
		require.NoError(t, err)
		require.NoError(t, store.SetUserBan(ctx, userID, &adminID, "incident"))
		require.NoError(t, store.SetUserBan(ctx, userID, nil, ""))

		_, _, err = store.UpsertRefreshSessionForActiveVersion(ctx, userID, 0, "device", "browser", []byte("stale"), expiresAt, 10)
		require.ErrorIs(t, err, ErrTokenVersionMismatch)
		row, err := store.GetRefreshByUserDevice(ctx, userID, "device")
		require.NoError(t, err)
		require.NotNil(t, row)
		require.Equal(t, originalHash, row.TokenHash)
		require.NotNil(t, row.RevokedAt)
	})

	t.Run("rotation commits before ban and the rotated session is revoked", func(t *testing.T) {
		userID := newUser(t, "rotate-first")
		oldHash := []byte("old-rotate-first")
		_, sessionID, err := store.UpsertRefreshSessionForActiveVersion(ctx, userID, 0, "device", "browser", oldHash, expiresAt, 10)
		require.NoError(t, err)
		locked := make(chan struct{})
		release := make(chan struct{})
		rotateResult := make(chan error, 1)
		newHash := []byte("new-rotate-first")
		go func() {
			_, rotateErr := store.rotateRefreshSessionForActiveVersion(
				ctx, userID, sessionID, 0, oldHash, newHash, expiresAt, func() { close(locked); <-release },
			)
			rotateResult <- rotateErr
		}()
		<-locked
		banStarted := make(chan struct{})
		banResult := make(chan error, 1)
		go func() {
			close(banStarted)
			banResult <- store.SetUserBan(ctx, userID, &adminID, "incident")
		}()
		<-banStarted
		close(release)
		require.NoError(t, <-rotateResult)
		require.NoError(t, <-banResult)

		row, err := store.GetRefreshByID(ctx, sessionID)
		require.NoError(t, err)
		require.Equal(t, newHash, row.TokenHash)
		require.NotNil(t, row.RevokedAt)
	})

	t.Run("ban commits before rotation and rotation cannot mutate", func(t *testing.T) {
		userID := newUser(t, "ban-first-rotate")
		oldHash := []byte("old-ban-first")
		_, sessionID, err := store.UpsertRefreshSessionForActiveVersion(ctx, userID, 0, "device", "browser", oldHash, expiresAt, 10)
		require.NoError(t, err)
		locked := make(chan struct{})
		release := make(chan struct{})
		banResult := make(chan error, 1)
		go func() {
			banResult <- store.setUserBan(ctx, userID, &adminID, "incident", func() { close(locked); <-release })
		}()
		<-locked
		rotateStarted := make(chan struct{})
		rotateResult := make(chan error, 1)
		go func() {
			close(rotateStarted)
			_, rotateErr := store.RotateRefreshSessionForActiveVersion(ctx, userID, sessionID, 0, oldHash, []byte("must-not-write"), expiresAt)
			rotateResult <- rotateErr
		}()
		<-rotateStarted
		close(release)
		require.NoError(t, <-banResult)
		require.ErrorIs(t, <-rotateResult, ErrUserInactive)

		row, err := store.GetRefreshByID(ctx, sessionID)
		require.NoError(t, err)
		require.Equal(t, oldHash, row.TokenHash)
		require.NotNil(t, row.RevokedAt)
	})

	t.Run("the same refresh token rotates exactly once", func(t *testing.T) {
		userID := newUser(t, "double-rotate")
		oldHash := []byte("old-double")
		_, sessionID, err := store.UpsertRefreshSessionForActiveVersion(ctx, userID, 0, "device", "browser", oldHash, expiresAt, 10)
		require.NoError(t, err)

		start := make(chan struct{})
		results := make(chan error, 2)
		var ready sync.WaitGroup
		ready.Add(2)
		for i := 0; i < 2; i++ {
			newHash := []byte{byte('a' + i)}
			go func() {
				ready.Done()
				<-start
				_, rotateErr := store.RotateRefreshSessionForActiveVersion(ctx, userID, sessionID, 0, oldHash, newHash, expiresAt)
				results <- rotateErr
			}()
		}
		ready.Wait()
		close(start)
		errs := []error{<-results, <-results}
		successes := 0
		invalid := 0
		for _, result := range errs {
			if result == nil {
				successes++
			} else if errors.Is(result, ErrRefreshInvalid) {
				invalid++
			}
		}
		require.Equal(t, 1, successes)
		require.Equal(t, 1, invalid)
	})

	t.Run("same-device upsert enforces the active session cap", func(t *testing.T) {
		userID := newUser(t, "session-cap")
		_, firstID, err := store.UpsertRefreshSessionForActiveVersion(ctx, userID, 0, "first", "browser", []byte("first"), expiresAt, 1)
		require.NoError(t, err)
		_, repeatedID, err := store.UpsertRefreshSessionForActiveVersion(ctx, userID, 0, "first", "browser", []byte("first-new"), expiresAt, 1)
		require.NoError(t, err)
		require.Equal(t, firstID, repeatedID, "replacing the active device must not consume another slot")
		require.NoError(t, store.RevokeRefreshSession(ctx, firstID))
		_, _, err = store.UpsertRefreshSessionForActiveVersion(ctx, userID, 0, "second", "browser", []byte("second"), expiresAt, 1)
		require.NoError(t, err)
		_, revivedID, err := store.UpsertRefreshSessionForActiveVersion(ctx, userID, 0, "first", "browser", []byte("first-revived"), expiresAt, 1)
		require.NoError(t, err)
		require.Equal(t, firstID, revivedID)
		active, err := store.CountActiveRefreshSessions(ctx, userID)
		require.NoError(t, err)
		require.EqualValues(t, 1, active)
		second, err := store.GetRefreshByUserDevice(ctx, userID, "second")
		require.NoError(t, err)
		require.Nil(t, second, "reactivating a device at capacity evicts an active session inside the same transaction")
	})

	t.Run("invalid session caps fail before mutating an existing device", func(t *testing.T) {
		for _, maxSessions := range []int{0, -1} {
			userID := newUser(t, fmt.Sprintf("invalid-cap-%d", -maxSessions))
			originalHash := []byte("original-invalid-cap")
			originalExpiry := time.Now().Add(2 * time.Hour).Round(time.Microsecond)
			_, sessionID, err := store.UpsertRefreshSessionForActiveVersion(
				ctx, userID, 0, "device", "original label", originalHash, originalExpiry, 1,
			)
			require.NoError(t, err)

			_, returnedID, err := store.UpsertRefreshSessionForActiveVersion(
				ctx, userID, 0, "device", "changed label", []byte("changed"), time.Now().Add(24*time.Hour), maxSessions,
			)
			require.ErrorIs(t, err, ErrInvalidMaxSessions)
			require.Equal(t, uuid.Nil, returnedID)

			row, getErr := store.GetRefreshByUserDevice(ctx, userID, "device")
			require.NoError(t, getErr)
			require.NotNil(t, row)
			require.Equal(t, sessionID, row.ID)
			require.Equal(t, originalHash, row.TokenHash)
			require.Equal(t, originalExpiry, row.ExpiresAt)
			require.NotNil(t, row.DeviceLabel)
			require.Equal(t, "original label", *row.DeviceLabel)
			rows, listErr := store.ListRefreshSessions(ctx, userID)
			require.NoError(t, listErr)
			require.Len(t, rows, 1)
		}
	})

	t.Run("lowered cap preserves the requested active device while evicting peers", func(t *testing.T) {
		userID := newUser(t, "lowered-cap-same-device")
		devices := []string{"oldest", "middle", "newest"}
		ids := make(map[string]uuid.UUID, len(devices))
		for _, device := range devices {
			_, id, err := store.UpsertRefreshSessionForActiveVersion(
				ctx, userID, 0, device, "browser", []byte(device), expiresAt, 3,
			)
			require.NoError(t, err)
			ids[device] = id
		}
		base := time.Now().Add(-time.Hour)
		for i, device := range devices {
			require.NoError(t, db.Exec("UPDATE refresh_sessions SET created_at = ? WHERE id = ?", base.Add(time.Duration(i)*time.Minute), ids[device]).Error)
		}

		_, requestedID, err := store.UpsertRefreshSessionForActiveVersion(
			ctx, userID, 0, "oldest", "updated browser", []byte("oldest-updated"), expiresAt, 2,
		)
		require.NoError(t, err)
		require.Equal(t, ids["oldest"], requestedID)
		active, err := store.CountActiveRefreshSessions(ctx, userID)
		require.NoError(t, err)
		require.EqualValues(t, 2, active)
		oldest, err := store.GetRefreshByUserDevice(ctx, userID, "oldest")
		require.NoError(t, err)
		require.NotNil(t, oldest)
		require.Equal(t, []byte("oldest-updated"), oldest.TokenHash)
		middle, err := store.GetRefreshByUserDevice(ctx, userID, "middle")
		require.NoError(t, err)
		require.Nil(t, middle, "the oldest peer, not the requested active device, must be evicted")
		newest, err := store.GetRefreshByUserDevice(ctx, userID, "newest")
		require.NoError(t, err)
		require.NotNil(t, newest)
	})
}
