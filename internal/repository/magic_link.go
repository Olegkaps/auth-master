package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func (s *Store) InsertMagicLink(ctx context.Context, tokenHash []byte, userID uuid.UUID, expiresAt time.Time) (uuid.UUID, error) {
	row := magicLinkModel{TokenHash: tokenHash, UserID: userID, ExpiresAt: expiresAt}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return uuid.Nil, err
	}
	return row.ID, nil
}

// ConsumeMagicLink atomically marks a valid (unused, unexpired) link as used and
// returns the owning user id. Returns (uuid.Nil, nil) when there is no match.
func (s *Store) ConsumeMagicLink(ctx context.Context, tokenHash []byte) (uuid.UUID, error) {
	var userID uuid.UUID
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var m magicLinkModel
		e := tx.Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", tokenHash, time.Now()).Take(&m).Error
		if errors.Is(e, gorm.ErrRecordNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		res := tx.Model(&magicLinkModel{}).Where("id = ? AND used_at IS NULL", m.ID).Update("used_at", time.Now())
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return nil // lost the race; treat as invalid
		}
		userID = m.UserID
		return nil
	})
	return userID, err
}
