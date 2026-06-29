package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"gorm.io/gorm"
)

func (s *Store) CreateHumanUser(ctx context.Context, login, email, passwordHash string) (uuid.UUID, error) {
	em := strings.TrimSpace(email)
	u := userModel{
		Login:             login,
		Email:             &em,
		Kind:              "human",
		PasswordHash:      &passwordHash,
		PasswordChangedAt: ptrTime(time.Now()),
	}
	if err := s.db.WithContext(ctx).Create(&u).Error; err != nil {
		return uuid.Nil, err
	}
	return u.ID, nil
}

func (s *Store) CreateServiceUser(ctx context.Context, login, secretHash string) (uuid.UUID, error) {
	u := userModel{
		Login:             login,
		Kind:              "service",
		ServiceSecretHash: &secretHash,
	}
	if err := s.db.WithContext(ctx).Create(&u).Error; err != nil {
		return uuid.Nil, err
	}
	return u.ID, nil
}

func (s *Store) GetUserByLogin(ctx context.Context, login string) (*domain.User, error) {
	var m userModel
	err := s.db.WithContext(ctx).Where("LOWER(login) = ?", strings.ToLower(login)).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rowToUser(&m), nil
}

func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	var m userModel
	err := s.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rowToUser(&m), nil
}

func rowToUser(m *userModel) *domain.User {
	return &domain.User{
		ID:                m.ID,
		Login:             m.Login,
		Email:             m.Email,
		Kind:              domain.UserKind(m.Kind),
		PasswordHash:      m.PasswordHash,
		ServiceSecretHash: m.ServiceSecretHash,
		Superuser:         m.Superuser,
		PasswordChangedAt: m.PasswordChangedAt,
		LockedUntil:       m.LockedUntil,
		CreatedAt:         m.CreatedAt,
	}
}

func (s *Store) SetLockedUntil(ctx context.Context, userID uuid.UUID, t *time.Time) error {
	return s.db.WithContext(ctx).Model(&userModel{}).Where("id = ?", userID).Updates(map[string]any{
		"locked_until": t,
	}).Error
}

func (s *Store) UpdatePassword(ctx context.Context, userID uuid.UUID, hash string) error {
	return s.db.WithContext(ctx).Model(&userModel{}).Where("id = ?", userID).Updates(map[string]any{
		"password_hash":       hash,
		"password_changed_at": time.Now(),
	}).Error
}

type PasswordHistoryEntry struct {
	PasswordHash string
	Ciphertext   []byte
	Nonce        []byte
}

func (s *Store) ListPasswordHistory(ctx context.Context, userID uuid.UUID, limit int) ([]PasswordHistoryEntry, error) {
	var rows []passwordHistoryModel
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]PasswordHistoryEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, PasswordHistoryEntry{
			PasswordHash: r.PasswordHash,
			Ciphertext:   r.Ciphertext,
			Nonce:        r.Nonce,
		})
	}
	return out, nil
}

func (s *Store) InsertPasswordHistory(ctx context.Context, userID uuid.UUID, hash string, ciphertext, nonce []byte) error {
	row := passwordHistoryModel{
		UserID:       userID,
		PasswordHash: hash,
		Ciphertext:   ciphertext,
		Nonce:        nonce,
	}
	return s.db.WithContext(ctx).Create(&row).Error
}

func (s *Store) TrimPasswordHistory(ctx context.Context, userID uuid.UUID, keep int) error {
	return s.db.WithContext(ctx).Exec(`
		DELETE FROM password_history WHERE id IN (
			SELECT id FROM password_history WHERE user_id = ? ORDER BY created_at DESC OFFSET ?
		)`, userID, keep).Error
}

func (s *Store) CountHumanUsers(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.WithContext(ctx).Model(&userModel{}).Where("kind = ?", "human").Count(&n).Error
	return n, err
}

func (s *Store) SetSuperuser(ctx context.Context, userID uuid.UUID, v bool) error {
	return s.db.WithContext(ctx).Model(&userModel{}).Where("id = ?", userID).Update("superuser", v).Error
}

func (s *Store) ListUsers(ctx context.Context, limit int) ([]domain.User, error) {
	var rows []userModel
	if err := s.db.WithContext(ctx).Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	list := make([]domain.User, 0, len(rows))
	for i := range rows {
		list = append(list, *rowToUser(&rows[i]))
	}
	return list, nil
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
