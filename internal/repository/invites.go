package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

// RegisterHumanWithInvite claims an invite and creates the complete account in
// one transaction. The row lock makes concurrent replays deterministic: at
// most one caller can create a user from a one-time invite.
func (s *Store) RegisterHumanWithInvite(
	ctx context.Context,
	tokenHash []byte,
	login, email, passwordHash string,
	historyCipher, historyNonce []byte,
	historyKeep int,
) (uuid.UUID, bool, error) {
	var userID uuid.UUID
	registered := false
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var invite registrationInviteModel
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", tokenHash, time.Now()).
			Take(&invite).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		email = strings.TrimSpace(email)
		if invite.Email != nil && strings.TrimSpace(*invite.Email) != "" && !strings.EqualFold(email, strings.TrimSpace(*invite.Email)) {
			return nil
		}
		now := time.Now()
		user := userModel{
			Login: login, Email: &email, Kind: "human", PasswordHash: &passwordHash,
			PasswordChangedAt: &now, Superuser: invite.Superuser,
		}
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		userID = user.ID
		if err := tx.Create(&passwordHistoryModel{
			UserID: user.ID, PasswordHash: passwordHash, Ciphertext: historyCipher, Nonce: historyNonce,
		}).Error; err != nil {
			return err
		}
		if historyKeep > 0 {
			if err := tx.Exec(`DELETE FROM password_history WHERE id IN (
				SELECT id FROM password_history WHERE user_id = ? ORDER BY created_at DESC OFFSET ?
			)`, user.ID, historyKeep).Error; err != nil {
				return err
			}
		}
		result := tx.Model(&registrationInviteModel{}).
			Where("id = ? AND used_at IS NULL", invite.ID).
			Update("used_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errors.New("invite already used")
		}
		registered = true
		return nil
	})
	return userID, registered, err
}
