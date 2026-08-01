package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// StepUp2FASession is an email OTP step-up challenge (table grpc_two_fa_sessions).
type StepUp2FASession struct {
	ID            uuid.UUID
	CorrelationID string
	UserID        uuid.UUID
	Status        string
	ExpiresAt     time.Time
	ResolvedAt    *time.Time
}

func (s *Store) CreateStepUp2FASession(ctx context.Context, correlationID string, userID uuid.UUID, expiresAt time.Time) error {
	row := stepUp2FAModel{
		CorrelationID: correlationID,
		UserID:        userID,
		ExpiresAt:     expiresAt,
		Status:        "pending",
	}
	return s.db.WithContext(ctx).Create(&row).Error
}

func (s *Store) GetStepUp2FA(ctx context.Context, correlationID string) (*StepUp2FASession, error) {
	var m stepUp2FAModel
	err := s.db.WithContext(ctx).Where("correlation_id = ?", correlationID).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return stepUp2FAOut(&m), nil
}

func stepUp2FAOut(m *stepUp2FAModel) *StepUp2FASession {
	return &StepUp2FASession{
		ID: m.ID, CorrelationID: m.CorrelationID, UserID: m.UserID,
		Status: m.Status, ExpiresAt: m.ExpiresAt, ResolvedAt: m.ResolvedAt,
	}
}

func (s *Store) ApproveStepUp2FA(ctx context.Context, correlationID string) error {
	res := s.db.WithContext(ctx).Model(&stepUp2FAModel{}).
		Where("correlation_id = ? AND status = ?", correlationID, "pending").
		Updates(map[string]any{"status": "approved", "resolved_at": time.Now()})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("no pending session")
	}
	return nil
}

func (s *Store) ExpireStepUp2FA(ctx context.Context, correlationID string) error {
	return s.db.WithContext(ctx).Model(&stepUp2FAModel{}).
		Where("correlation_id = ? AND status = ?", correlationID, "pending").
		Updates(map[string]any{"status": "expired", "resolved_at": time.Now()}).Error
}

func (s *Store) MarkExpiredStepUp2FAByTime(ctx context.Context, now time.Time) error {
	return s.db.WithContext(ctx).Model(&stepUp2FAModel{}).
		Where("status = ? AND expires_at < ?", "pending", now).
		Updates(map[string]any{"status": "expired", "resolved_at": time.Now()}).Error
}
