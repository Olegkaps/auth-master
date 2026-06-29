package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"gorm.io/gorm"
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
	CodeHash     []byte
	ExpiresAt    time.Time
	ConsumedAt   *time.Time
	AttemptCount int
	Correlation  *string
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

func otpRow(m *emailOTPModel) *OTPRow {
	return &OTPRow{
		ID: m.ID, UserID: m.UserID, CodeHash: m.CodeHash, ExpiresAt: m.ExpiresAt,
		ConsumedAt: m.ConsumedAt, AttemptCount: m.AttemptCount, Correlation: m.CorrelationID,
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
