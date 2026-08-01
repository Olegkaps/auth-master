package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type RegistrationInvite struct {
	ID        uuid.UUID
	Email     *string
	Superuser bool
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedBy uuid.UUID
}

func (s *Store) InsertRegistrationInvite(ctx context.Context, tokenHash []byte, email *string, superuser bool, expiresAt time.Time, createdBy uuid.UUID) (uuid.UUID, error) {
	row := registrationInviteModel{
		TokenHash: tokenHash,
		Email:     email,
		Superuser: superuser,
		ExpiresAt: expiresAt,
		CreatedBy: createdBy,
	}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return uuid.Nil, err
	}
	return row.ID, nil
}

func (s *Store) GetValidRegistrationInviteByTokenHash(ctx context.Context, tokenHash []byte) (*RegistrationInvite, error) {
	var m registrationInviteModel
	err := s.db.WithContext(ctx).
		Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", tokenHash, time.Now()).
		Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &RegistrationInvite{
		ID: m.ID, Email: m.Email, Superuser: m.Superuser, ExpiresAt: m.ExpiresAt, UsedAt: m.UsedAt, CreatedBy: m.CreatedBy,
	}, nil
}

func (s *Store) MarkRegistrationInviteUsed(ctx context.Context, id uuid.UUID) error {
	res := s.db.WithContext(ctx).Model(&registrationInviteModel{}).
		Where("id = ? AND used_at IS NULL", id).
		Update("used_at", time.Now())
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("invite already used or missing")
	}
	return nil
}
