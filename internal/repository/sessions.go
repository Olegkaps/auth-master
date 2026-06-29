package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"gorm.io/gorm"
)

func (s *Store) CountActiveRefreshSessions(ctx context.Context, userID uuid.UUID) (int64, error) {
	var n int64
	err := s.db.WithContext(ctx).Model(&refreshSessionModel{}).
		Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", userID, time.Now()).
		Count(&n).Error
	return n, err
}

func (s *Store) DeleteOldestRefreshSession(ctx context.Context, userID uuid.UUID) error {
	return s.db.WithContext(ctx).Exec(`
		DELETE FROM refresh_sessions WHERE id = (
			SELECT id FROM refresh_sessions WHERE user_id = ? AND revoked_at IS NULL
			ORDER BY created_at ASC LIMIT 1
		)`, userID).Error
}

func (s *Store) UpsertRefreshSession(ctx context.Context, userID uuid.UUID, deviceID, deviceLabel string, tokenHash []byte, expiresAt time.Time) (uuid.UUID, error) {
	newID := uuid.New()
	var idStr string
	err := s.db.WithContext(ctx).Raw(`
		INSERT INTO refresh_sessions (id, user_id, device_id, device_label, token_hash, expires_at)
		VALUES (?,?,?,NULLIF(?,''),?,?)
		ON CONFLICT (user_id, device_id) DO UPDATE SET
			token_hash = EXCLUDED.token_hash,
			expires_at = EXCLUDED.expires_at,
			used_at = NULL,
			revoked_at = NULL,
			device_label = COALESCE(EXCLUDED.device_label, refresh_sessions.device_label),
			created_at = now()
		RETURNING id`,
		newID, userID, deviceID, deviceLabel, tokenHash, expiresAt).Scan(&idStr).Error
	if err != nil {
		return uuid.Nil, err
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

func (s *Store) ReplaceRefreshToken(ctx context.Context, id uuid.UUID, oldHash, newHash []byte, expiresAt time.Time) error {
	res := s.db.WithContext(ctx).Exec(`
		UPDATE refresh_sessions SET token_hash = ?, expires_at = ?, used_at = NULL
		WHERE id = ? AND token_hash = ? AND used_at IS NULL AND revoked_at IS NULL`,
		newHash, expiresAt, id, oldHash)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("refresh token already used or mismatch")
	}
	return nil
}

type RefreshRow struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	DeviceID    string
	DeviceLabel *string
	TokenHash   []byte
	ExpiresAt   time.Time
	UsedAt      *time.Time
	RevokedAt   *time.Time
}

func (s *Store) GetRefreshByUserDevice(ctx context.Context, userID uuid.UUID, deviceID string) (*RefreshRow, error) {
	var m refreshSessionModel
	err := s.db.WithContext(ctx).Where("user_id = ? AND device_id = ?", userID, deviceID).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return refreshRow(&m), nil
}

func (s *Store) GetRefreshByID(ctx context.Context, id uuid.UUID) (*RefreshRow, error) {
	var m refreshSessionModel
	err := s.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return refreshRow(&m), nil
}

func refreshRow(m *refreshSessionModel) *RefreshRow {
	return &RefreshRow{
		ID:          m.ID,
		UserID:      m.UserID,
		DeviceID:    m.DeviceID,
		DeviceLabel: m.DeviceLabel,
		TokenHash:   m.TokenHash,
		ExpiresAt:   m.ExpiresAt,
		UsedAt:      m.UsedAt,
		RevokedAt:   m.RevokedAt,
	}
}

func (s *Store) ListRefreshSessions(ctx context.Context, userID uuid.UUID) ([]domain.RefreshSession, error) {
	var rows []refreshSessionModel
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	list := make([]domain.RefreshSession, 0, len(rows))
	for _, m := range rows {
		list = append(list, domain.RefreshSession{
			ID:          m.ID,
			UserID:      m.UserID,
			DeviceID:    m.DeviceID,
			DeviceLabel: m.DeviceLabel,
			CreatedAt:   m.CreatedAt,
			ExpiresAt:   m.ExpiresAt,
			UsedAt:      m.UsedAt,
			RevokedAt:   m.RevokedAt,
		})
	}
	return list, nil
}

func (s *Store) MarkRefreshUsed(ctx context.Context, id uuid.UUID) error {
	return s.db.WithContext(ctx).Model(&refreshSessionModel{}).
		Where("id = ? AND used_at IS NULL", id).
		Update("used_at", time.Now()).Error
}

func (s *Store) RevokeRefreshSession(ctx context.Context, id uuid.UUID) error {
	return s.db.WithContext(ctx).Model(&refreshSessionModel{}).Where("id = ?", id).
		Update("revoked_at", time.Now()).Error
}

func (s *Store) RevokeRefreshByHash(ctx context.Context, userID uuid.UUID, tokenHash []byte) error {
	return s.db.WithContext(ctx).Model(&refreshSessionModel{}).
		Where("user_id = ? AND token_hash = ? AND revoked_at IS NULL", userID, tokenHash).
		Update("revoked_at", time.Now()).Error
}

func (s *Store) FindRefreshByTokenHash(ctx context.Context, tokenHash []byte) (*RefreshRow, error) {
	var m refreshSessionModel
	err := s.db.WithContext(ctx).
		Where("token_hash = ? AND revoked_at IS NULL AND expires_at > ?", tokenHash, time.Now()).
		Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return refreshRow(&m), nil
}
