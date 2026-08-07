package repository

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Store) CreateEmailOTP(ctx context.Context, userID uuid.UUID, purpose domain.OTPPurpose, codeHash []byte, expiresAt time.Time, correlation *string) (uuid.UUID, error) {
	row := emailOTPModel{
		UserID:        userID,
		Purpose:       string(purpose),
		CodeHash:      codeHash,
		ExpiresAt:     expiresAt,
		CorrelationID: correlation,
	}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return uuid.Nil, err
	}
	return row.ID, nil
}

type OTPRow struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	Purpose      domain.OTPPurpose
	CodeHash     []byte
	ExpiresAt    time.Time
	ConsumedAt   *time.Time
	AttemptCount int
	Correlation  *string
	CreatedAt    time.Time
}

func (s *Store) GetLatestOTP(ctx context.Context, userID uuid.UUID, purpose domain.OTPPurpose) (*OTPRow, error) {
	var m emailOTPModel
	err := s.db.WithContext(ctx).
		Where("user_id = ? AND purpose = ? AND consumed_at IS NULL", userID, string(purpose)).
		Order("created_at DESC").
		Limit(1).
		Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return otpRow(&m), nil
}

func (s *Store) GetOTPByCorrelation(ctx context.Context, correlation string) (*OTPRow, error) {
	var m emailOTPModel
	err := s.db.WithContext(ctx).
		Where("correlation_id = ? AND consumed_at IS NULL", correlation).
		Order("created_at DESC").
		Limit(1).
		Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return otpRow(&m), nil
}

// GetMostRecentOTP returns the newest challenge including consumed challenges.
// Issuance throttling uses it so consuming a code cannot bypass the cooldown.
func (s *Store) GetMostRecentOTP(ctx context.Context, userID uuid.UUID, purpose domain.OTPPurpose) (*OTPRow, error) {
	var m emailOTPModel
	err := s.db.WithContext(ctx).
		Where("user_id = ? AND purpose = ?", userID, string(purpose)).
		Order("created_at DESC").
		Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return otpRow(&m), nil
}

// IssuePasswordResetOTP serializes issuance for one user, enforces the
// cooldown against consumed challenges too, invalidates every older active
// reset code, and inserts exactly one replacement challenge.
func (s *Store) IssuePasswordResetOTP(
	ctx context.Context,
	userID uuid.UUID,
	codeHash []byte,
	now, expiresAt time.Time,
	minInterval time.Duration,
) (uuid.UUID, bool, error) {
	var id uuid.UUID
	issued := false
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockOTPUser(tx, userID); err != nil {
			return err
		}
		var latest emailOTPModel
		err := tx.Where("user_id = ? AND purpose = ?", userID, string(domain.OTPPasswordReset)).
			Order("created_at DESC, id DESC").Take(&latest).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err == nil && minInterval > 0 && now.Sub(latest.CreatedAt) < minInterval {
			return nil
		}
		if err := tx.Model(&emailOTPModel{}).
			Where("user_id = ? AND purpose = ? AND consumed_at IS NULL", userID, string(domain.OTPPasswordReset)).
			Update("consumed_at", now).Error; err != nil {
			return err
		}
		row := emailOTPModel{
			UserID: userID, Purpose: string(domain.OTPPasswordReset), CodeHash: codeHash, ExpiresAt: expiresAt,
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		id = row.ID
		issued = true
		return nil
	})
	return id, issued, err
}

// CompletePasswordResetOTP serializes against issuance and other completions.
// Wrong-code accounting commits independently. For a correct code, preparation,
// password mutation, history insertion/trimming, and OTP consumption are one
// transaction: any callback or database error leaves every value unchanged.
func (s *Store) CompletePasswordResetOTP(
	ctx context.Context,
	userID uuid.UUID,
	candidateHash []byte,
	now time.Time,
	maxAttempts, historyLimit int,
	prepare PasswordResetPreparer,
) (bool, error) {
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	completed := false
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockOTPUser(tx, userID); err != nil {
			return err
		}
		var row emailOTPModel
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("user_id = ? AND purpose = ? AND consumed_at IS NULL", userID, string(domain.OTPPasswordReset)).
			Order("created_at DESC, id DESC").Take(&row).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !now.Before(row.ExpiresAt) || row.AttemptCount >= maxAttempts {
			return tx.Model(&emailOTPModel{}).Where("id = ? AND consumed_at IS NULL", row.ID).Update("consumed_at", now).Error
		}
		if subtle.ConstantTimeCompare(candidateHash, row.CodeHash) == 1 {
			if prepare == nil {
				return errors.New("password reset preparer is required")
			}
			var historyRows []passwordHistoryModel
			if historyLimit > 0 {
				if err := tx.Where("user_id = ?", userID).
					Order("created_at DESC, id DESC").Limit(historyLimit).Find(&historyRows).Error; err != nil {
					return err
				}
			}
			history := make([]PasswordHistoryEntry, 0, len(historyRows))
			for _, item := range historyRows {
				history = append(history, PasswordHistoryEntry{
					PasswordHash: item.PasswordHash, Ciphertext: item.Ciphertext, Nonce: item.Nonce,
				})
			}
			mutation, err := prepare(history)
			if err != nil {
				return err
			}
			if mutation.PasswordHash == "" || len(mutation.Ciphertext) == 0 || len(mutation.Nonce) == 0 {
				return errors.New("incomplete password reset mutation")
			}
			passwordUpdate := tx.Model(&userModel{}).Where("id = ?", userID).Updates(map[string]any{
				"password_hash": mutation.PasswordHash, "password_changed_at": now,
			})
			if passwordUpdate.Error != nil {
				return passwordUpdate.Error
			}
			if passwordUpdate.RowsAffected != 1 {
				return errors.New("password reset user missing")
			}
			historyEntry := passwordHistoryModel{
				UserID: userID, PasswordHash: mutation.PasswordHash, Ciphertext: mutation.Ciphertext, Nonce: mutation.Nonce, CreatedAt: now,
			}
			historyInsert := tx.Create(&historyEntry)
			if historyInsert.Error != nil {
				return historyInsert.Error
			}
			if historyInsert.RowsAffected != 1 {
				return errors.New("password reset history insert failed")
			}
			if historyLimit >= 0 {
				if err := tx.Exec(`DELETE FROM password_history WHERE id IN (
					SELECT id FROM password_history WHERE user_id = ?
					ORDER BY created_at DESC, id DESC OFFSET ?
				)`, userID, historyLimit).Error; err != nil {
					return err
				}
			}
			consumed := tx.Model(&emailOTPModel{}).
				Where("id = ? AND consumed_at IS NULL", row.ID).Update("consumed_at", now)
			if consumed.Error != nil {
				return consumed.Error
			}
			if consumed.RowsAffected != 1 {
				return errors.New("password reset OTP already consumed")
			}
			completed = true
			return nil
		}
		nextAttempts := row.AttemptCount + 1
		updates := map[string]any{"attempt_count": nextAttempts}
		if nextAttempts >= maxAttempts {
			updates["consumed_at"] = now
		}
		return tx.Model(&emailOTPModel{}).Where("id = ? AND consumed_at IS NULL", row.ID).Updates(updates).Error
	})
	if err != nil {
		return false, err
	}
	return completed, nil
}

func lockOTPUser(tx *gorm.DB, userID uuid.UUID) error {
	var user userModel
	return tx.Select("id").Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", userID).Take(&user).Error
}

func otpRow(m *emailOTPModel) *OTPRow {
	return &OTPRow{
		ID: m.ID, UserID: m.UserID, Purpose: domain.OTPPurpose(m.Purpose), CodeHash: m.CodeHash, ExpiresAt: m.ExpiresAt,
		ConsumedAt: m.ConsumedAt, AttemptCount: m.AttemptCount, Correlation: m.CorrelationID, CreatedAt: m.CreatedAt,
	}
}

func (s *Store) ConsumeOTP(ctx context.Context, id uuid.UUID) error {
	res := s.db.WithContext(ctx).Model(&emailOTPModel{}).
		Where("id = ? AND consumed_at IS NULL", id).
		Update("consumed_at", time.Now())
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("otp already consumed or missing")
	}
	return nil
}

func (s *Store) IncrementOTPAttempt(ctx context.Context, id uuid.UUID) error {
	return s.db.WithContext(ctx).Model(&emailOTPModel{}).Where("id = ?", id).
		UpdateColumn("attempt_count", gorm.Expr("attempt_count + 1")).Error
}
