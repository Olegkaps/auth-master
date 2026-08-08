package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrUserInactive         = errors.New("user is inactive")
	ErrTokenVersionMismatch = errors.New("token version mismatch")
	ErrRefreshInvalid       = errors.New("refresh token is invalid")
	ErrInvalidMaxSessions   = errors.New("maximum sessions per user must be positive")
)

// UpsertRefreshSessionForActiveVersion creates or replaces a device session
// only while the user is active and still has the version observed by the
// caller. Locking the user serializes issuance with bans and other issuance.
func (s *Store) UpsertRefreshSessionForActiveVersion(
	ctx context.Context,
	userID uuid.UUID,
	expectedTokenVersion int64,
	deviceID, deviceLabel string,
	tokenHash []byte,
	expiresAt time.Time,
	maxSessions int,
) (*domain.User, uuid.UUID, error) {
	return s.upsertRefreshSessionForActiveVersion(ctx, userID, expectedTokenVersion, deviceID, deviceLabel, tokenHash, expiresAt, maxSessions, nil)
}

func (s *Store) upsertRefreshSessionForActiveVersion(
	ctx context.Context,
	userID uuid.UUID,
	expectedTokenVersion int64,
	deviceID, deviceLabel string,
	tokenHash []byte,
	expiresAt time.Time,
	maxSessions int,
	afterUserLocked func(),
) (*domain.User, uuid.UUID, error) {
	if maxSessions <= 0 {
		return nil, uuid.Nil, ErrInvalidMaxSessions
	}
	var lockedUser *domain.User
	var sessionID uuid.UUID
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user userModel
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", userID).Take(&user).Error; err != nil {
			return err
		}
		if afterUserLocked != nil {
			afterUserLocked()
		}
		now := time.Now()
		if user.BannedAt != nil {
			return ErrUserInactive
		}
		if user.TokenVersion != expectedTokenVersion {
			return ErrTokenVersionMismatch
		}

		var existing refreshSessionModel
		existingErr := tx.Where("user_id = ? AND device_id = ?", userID, deviceID).Take(&existing).Error
		if existingErr != nil && !errors.Is(existingErr, gorm.ErrRecordNotFound) {
			return existingErr
		}
		var active int64
		if err := tx.Model(&refreshSessionModel{}).
			Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", userID, now).
			Count(&active).Error; err != nil {
			return err
		}
		existingIsActive := existingErr == nil && existing.RevokedAt == nil && existing.ExpiresAt.After(now)
		projected := active
		if !existingIsActive {
			projected++
		}
		for projected > int64(maxSessions) {
			result := tx.Exec(`
					DELETE FROM refresh_sessions WHERE id = (
						SELECT id FROM refresh_sessions
						WHERE user_id = ? AND device_id <> ? AND revoked_at IS NULL AND expires_at > ?
						ORDER BY created_at ASC, id ASC LIMIT 1
					)`, userID, deviceID, now)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return errors.New("active refresh session count changed unexpectedly")
			}
			projected--
		}

		newID := uuid.New()
		var idStr string
		if err := tx.Raw(`
			INSERT INTO refresh_sessions (id, user_id, device_id, device_label, token_hash, expires_at, created_at)
			VALUES (?,?,?,NULLIF(?,''),?,?, now())
			ON CONFLICT (user_id, device_id) DO UPDATE SET
				token_hash = EXCLUDED.token_hash,
				expires_at = EXCLUDED.expires_at,
				used_at = NULL,
				revoked_at = NULL,
				device_label = COALESCE(EXCLUDED.device_label, refresh_sessions.device_label),
				created_at = now()
			RETURNING id`,
			newID, userID, deviceID, deviceLabel, tokenHash, expiresAt).Scan(&idStr).Error; err != nil {
			return err
		}
		var err error
		sessionID, err = uuid.Parse(idStr)
		if err != nil {
			return err
		}
		lockedUser = rowToUser(&user)
		return nil
	})
	return lockedUser, sessionID, err
}

// RotateRefreshSessionForActiveVersion atomically verifies the user and the
// exact current session token before replacing it. Revoked rows are never
// revived by rotation.
func (s *Store) RotateRefreshSessionForActiveVersion(
	ctx context.Context,
	userID, sessionID uuid.UUID,
	expectedTokenVersion int64,
	oldHash, newHash []byte,
	expiresAt time.Time,
) (*domain.User, error) {
	return s.rotateRefreshSessionForActiveVersion(ctx, userID, sessionID, expectedTokenVersion, oldHash, newHash, expiresAt, nil)
}

func (s *Store) rotateRefreshSessionForActiveVersion(
	ctx context.Context,
	userID, sessionID uuid.UUID,
	expectedTokenVersion int64,
	oldHash, newHash []byte,
	expiresAt time.Time,
	afterUserLocked func(),
) (*domain.User, error) {
	var lockedUser *domain.User
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user userModel
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", userID).Take(&user).Error; err != nil {
			return err
		}
		if afterUserLocked != nil {
			afterUserLocked()
		}
		if user.BannedAt != nil {
			return ErrUserInactive
		}
		if user.TokenVersion != expectedTokenVersion {
			return ErrTokenVersionMismatch
		}

		var session refreshSessionModel
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND user_id = ? AND token_hash = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?",
				sessionID, userID, oldHash, time.Now()).Take(&session).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrRefreshInvalid
		}
		if err != nil {
			return err
		}
		result := tx.Model(&refreshSessionModel{}).
			Where("id = ? AND user_id = ? AND token_hash = ? AND used_at IS NULL AND revoked_at IS NULL", sessionID, userID, oldHash).
			Updates(map[string]any{"token_hash": newHash, "expires_at": expiresAt})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrRefreshInvalid
		}
		lockedUser = rowToUser(&user)
		return nil
	})
	return lockedUser, err
}

func (s *Store) CountActiveRefreshSessions(ctx context.Context, userID uuid.UUID) (int64, error) {
	var n int64
	err := s.db.WithContext(ctx).Model(&refreshSessionModel{}).
		Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", userID, time.Now()).
		Count(&n).Error
	return n, err
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
