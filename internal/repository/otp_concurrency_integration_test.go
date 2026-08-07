package repository

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestIntegration_PasswordResetOTPIssueAndCompleteAreLinearizable(t *testing.T) {
	s, cleanup := setupRepo(t)
	defer cleanup()
	ctx := context.Background()
	uid, err := s.CreateHumanUser(ctx, "otp-race", "otp-race@test.dev", "hash")
	require.NoError(t, err)

	now := time.Now()
	var issued atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, issueErr := s.IssuePasswordResetOTP(ctx, uid, []byte("first"), now, now.Add(time.Hour), time.Hour)
			require.NoError(t, issueErr)
			if ok {
				issued.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, issued.Load(), "concurrent issue calls must mint one challenge")
	require.EqualValues(t, 1, activeResetOTPCount(t, s, uid))

	_, replaced, err := s.IssuePasswordResetOTP(ctx, uid, []byte("second"), now.Add(2*time.Hour), now.Add(3*time.Hour), time.Hour)
	require.NoError(t, err)
	require.True(t, replaced)
	require.EqualValues(t, 1, activeResetOTPCount(t, s, uid), "replacement must invalidate the older active code")
	verified, err := s.CompletePasswordResetOTP(ctx, uid, []byte("first"), now.Add(2*time.Hour), 3, 5, resetMutation("first"))
	require.NoError(t, err)
	require.False(t, verified, "the replaced code must not verify")
	verified, err = s.CompletePasswordResetOTP(ctx, uid, []byte("second"), now.Add(2*time.Hour), 3, 5, resetMutation("second"))
	require.NoError(t, err)
	require.True(t, verified)
	require.EqualValues(t, 0, activeResetOTPCount(t, s, uid))
}

func TestIntegration_PasswordResetOTPAttemptCapAndDoubleSuccess(t *testing.T) {
	s, cleanup := setupRepo(t)
	defer cleanup()
	ctx := context.Background()
	uid, err := s.CreateHumanUser(ctx, "otp-cap", "otp-cap@test.dev", "hash")
	require.NoError(t, err)
	now := time.Now()
	_, ok, err := s.IssuePasswordResetOTP(ctx, uid, []byte("correct"), now, now.Add(time.Hour), 0)
	require.NoError(t, err)
	require.True(t, ok)

	var wrongAccepted atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			matched, verifyErr := s.CompletePasswordResetOTP(ctx, uid, []byte("wrong"), now, 3, 5, resetMutation("wrong"))
			require.NoError(t, verifyErr)
			if matched {
				wrongAccepted.Add(1)
			}
		}()
	}
	wg.Wait()
	require.Zero(t, wrongAccepted.Load())
	var row emailOTPModel
	require.NoError(t, s.db.Where("user_id = ? AND purpose = ?", uid, string(domain.OTPPasswordReset)).Order("created_at DESC, id DESC").Take(&row).Error)
	require.Equal(t, 3, row.AttemptCount)
	require.NotNil(t, row.ConsumedAt)
	matched, err := s.CompletePasswordResetOTP(ctx, uid, []byte("correct"), now, 3, 5, resetMutation("correct"))
	require.NoError(t, err)
	require.False(t, matched, "the correct code must not bypass a concurrently reached cap")

	uid2, err := s.CreateHumanUser(ctx, "otp-double", "otp-double@test.dev", "hash")
	require.NoError(t, err)
	_, ok, err = s.IssuePasswordResetOTP(ctx, uid2, []byte("correct"), now, now.Add(time.Hour), 0)
	require.NoError(t, err)
	require.True(t, ok)
	var successes atomic.Int32
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			accepted, verifyErr := s.CompletePasswordResetOTP(ctx, uid2, []byte("correct"), now, 3, 5, resetMutation("correct"))
			require.NoError(t, verifyErr)
			if accepted {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, successes.Load(), "a reset code must have exactly one successful consumer")
	history, err := s.ListPasswordHistory(ctx, uid2, 10)
	require.NoError(t, err)
	require.Len(t, history, 1, "concurrent completion must commit one password mutation")
}

func TestIntegration_PasswordResetOTPIssueVersusCompleteIsLinearizable(t *testing.T) {
	s, cleanup := setupRepo(t)
	defer cleanup()
	ctx := context.Background()
	uid, err := s.CreateHumanUser(ctx, "otp-linear", "otp-linear@test.dev", "hash")
	require.NoError(t, err)
	now := time.Now()
	_, ok, err := s.IssuePasswordResetOTP(ctx, uid, []byte("old"), now, now.Add(time.Hour), 0)
	require.NoError(t, err)
	require.True(t, ok)

	start := make(chan struct{})
	var oldVerified atomic.Bool
	var issueErr, verifyErr error
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		oldVerified.Store(func() bool {
			matched, err := s.CompletePasswordResetOTP(ctx, uid, []byte("old"), now.Add(time.Minute), 3, 5, resetMutation("old"))
			verifyErr = err
			return matched
		}())
	}()
	go func() {
		defer wg.Done()
		<-start
		_, _, issueErr = s.IssuePasswordResetOTP(ctx, uid, []byte("new"), now.Add(time.Minute), now.Add(time.Hour), 0)
	}()
	close(start)
	wg.Wait()
	require.NoError(t, issueErr)
	require.NoError(t, verifyErr)
	require.EqualValues(t, 1, activeResetOTPCount(t, s, uid), "the replacement remains the only active code in either serialization")
	newVerified, err := s.CompletePasswordResetOTP(ctx, uid, []byte("new"), now.Add(time.Minute), 3, 5, resetMutation("new"))
	require.NoError(t, err)
	require.True(t, newVerified)
	_ = oldVerified.Load() // Either result is valid depending on which locked transaction linearized first.
}

func resetMutation(password string) PasswordResetPreparer {
	return func([]PasswordHistoryEntry) (PasswordResetMutation, error) {
		return PasswordResetMutation{PasswordHash: "hash-" + password, Ciphertext: []byte("cipher-" + password), Nonce: []byte("nonce")}, nil
	}
}

func TestIntegration_PasswordResetCompletionRollbackAndDeterministicHistory(t *testing.T) {
	s, cleanup := setupRepo(t)
	defer cleanup()
	ctx := context.Background()
	uid, err := s.CreateHumanUser(ctx, "otp-atomic", "otp-atomic@test.dev", "old-hash")
	require.NoError(t, err)
	now := time.Now()
	_, issued, err := s.IssuePasswordResetOTP(ctx, uid, []byte("correct"), now, now.Add(time.Hour), 0)
	require.NoError(t, err)
	require.True(t, issued)

	prepareErr := errors.New("password policy rejected")
	completed, err := s.CompletePasswordResetOTP(ctx, uid, []byte("correct"), now.Add(time.Second), 3, 2,
		func([]PasswordHistoryEntry) (PasswordResetMutation, error) {
			return PasswordResetMutation{}, prepareErr
		})
	require.ErrorIs(t, err, prepareErr)
	require.False(t, completed)
	require.EqualValues(t, 1, activeResetOTPCount(t, s, uid), "callback errors must leave the correct OTP reusable")
	user, err := s.GetUserByID(ctx, uid)
	require.NoError(t, err)
	require.Equal(t, "old-hash", *user.PasswordHash)

	callbackCalled := false
	completed, err = s.CompletePasswordResetOTP(ctx, uid, []byte("wrong"), now.Add(2*time.Second), 3, 2,
		func([]PasswordHistoryEntry) (PasswordResetMutation, error) {
			callbackCalled = true
			return PasswordResetMutation{}, prepareErr
		})
	require.NoError(t, err)
	require.False(t, completed)
	require.False(t, callbackCalled, "wrong codes must be accounted before password preparation")
	var otp emailOTPModel
	require.NoError(t, s.db.Where("user_id = ? AND purpose = ?", uid, string(domain.OTPPasswordReset)).Take(&otp).Error)
	require.Equal(t, 1, otp.AttemptCount)
	require.Nil(t, otp.ConsumedAt)

	// Identical timestamps are trimmed by UUID as a deterministic tie-breaker.
	created := now.Add(-time.Hour)
	oldIDs := []uuid.UUID{
		uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		uuid.MustParse("00000000-0000-0000-0000-000000000002"),
		uuid.MustParse("00000000-0000-0000-0000-000000000003"),
	}
	for i, id := range oldIDs {
		require.NoError(t, s.db.Create(&passwordHistoryModel{
			ID: id, UserID: uid, PasswordHash: fmt.Sprintf("old-%d", i+1), Ciphertext: []byte("cipher"), Nonce: []byte("nonce"), CreatedAt: created,
		}).Error)
	}
	completed, err = s.CompletePasswordResetOTP(ctx, uid, []byte("correct"), now.Add(3*time.Second), 3, 2, resetMutation("valid"))
	require.NoError(t, err)
	require.True(t, completed)
	var kept []passwordHistoryModel
	require.NoError(t, s.db.Where("user_id = ?", uid).Order("created_at DESC, id DESC").Find(&kept).Error)
	require.Len(t, kept, 2)
	require.Equal(t, "hash-valid", kept[0].PasswordHash)
	require.Equal(t, oldIDs[2], kept[1].ID)
}

func TestIntegration_PasswordResetHistoryInsertFailureRollsBackEverything(t *testing.T) {
	s, cleanup := setupRepo(t)
	defer cleanup()
	ctx := context.Background()
	uid, err := s.CreateHumanUser(ctx, "otp-trigger", "otp-trigger@test.dev", "old-hash")
	require.NoError(t, err)
	require.NoError(t, s.InsertPasswordHistory(ctx, uid, "old-history", []byte("old-cipher"), []byte("old-nonce")))
	now := time.Now()
	_, issued, err := s.IssuePasswordResetOTP(ctx, uid, []byte("correct"), now, now.Add(time.Hour), 0)
	require.NoError(t, err)
	require.True(t, issued)

	require.NoError(t, s.db.Exec(`CREATE FUNCTION reject_reset_history() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.password_hash = 'hash-trigger' THEN RAISE EXCEPTION 'forced history failure'; END IF;
			RETURN NEW;
		END $$`).Error)
	require.NoError(t, s.db.Exec(`CREATE TRIGGER reject_reset_history BEFORE INSERT ON password_history
		FOR EACH ROW EXECUTE FUNCTION reject_reset_history()`).Error)

	completed, err := s.CompletePasswordResetOTP(ctx, uid, []byte("correct"), now.Add(time.Second), 3, 5, resetMutation("trigger"))
	require.Error(t, err)
	require.False(t, completed)
	user, getErr := s.GetUserByID(ctx, uid)
	require.NoError(t, getErr)
	require.Equal(t, "old-hash", *user.PasswordHash)
	history, historyErr := s.ListPasswordHistory(ctx, uid, 10)
	require.NoError(t, historyErr)
	require.Len(t, history, 1)
	require.Equal(t, "old-history", history[0].PasswordHash)
	require.EqualValues(t, 1, activeResetOTPCount(t, s, uid))
}

func activeResetOTPCount(t *testing.T, s *Store, userID any) int64 {
	t.Helper()
	var count int64
	require.NoError(t, s.db.Model(&emailOTPModel{}).
		Where("user_id = ? AND purpose = ? AND consumed_at IS NULL", userID, string(domain.OTPPasswordReset)).Count(&count).Error)
	return count
}
