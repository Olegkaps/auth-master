package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

type SigningKeyMaterial struct {
	Kid          string
	SecretCipher []byte
	Nonce        []byte
	DeprecatedAt *time.Time
	IsCurrent    bool
}

func (s *Store) GetSigningKeyMaterial(ctx context.Context, kid string) (*SigningKeyMaterial, error) {
	var m signingKeyModel
	err := s.db.WithContext(ctx).Where("kid = ?", kid).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return signingToMaterial(&m), nil
}

func (s *Store) GetCurrentSigningKeyMaterial(ctx context.Context) (*SigningKeyMaterial, error) {
	var m signingKeyModel
	err := s.db.WithContext(ctx).Where("is_current = ?", true).Limit(1).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return signingToMaterial(&m), nil
}

func signingToMaterial(m *signingKeyModel) *SigningKeyMaterial {
	return &SigningKeyMaterial{
		Kid: m.Kid, SecretCipher: m.SecretCipher, Nonce: m.Nonce,
		DeprecatedAt: m.DeprecatedAt, IsCurrent: m.IsCurrent,
	}
}

func (s *Store) InsertSigningKey(ctx context.Context, kid string, cipher, nonce []byte, deprecateOthers bool) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if deprecateOthers {
			if err := tx.Model(&signingKeyModel{}).Where("is_current = ?", true).Updates(map[string]any{
				"is_current":    false,
				"deprecated_at": gorm.Expr("COALESCE(deprecated_at, now())"),
			}).Error; err != nil {
				return err
			}
		}
		row := signingKeyModel{
			Kid: kid, SecretCipher: cipher, Nonce: nonce, IsCurrent: true, ValidFrom: time.Now(),
		}
		return tx.Create(&row).Error
	})
}

func (s *Store) DeprecateCurrentAndSet(ctx context.Context, newKid string, newCipher, newNonce []byte) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&signingKeyModel{}).Where("is_current = ?", true).Updates(map[string]any{
			"is_current":    false,
			"deprecated_at": time.Now(),
		}).Error; err != nil {
			return err
		}
		row := signingKeyModel{
			Kid: newKid, SecretCipher: newCipher, Nonce: newNonce, IsCurrent: true, ValidFrom: time.Now(),
		}
		return tx.Create(&row).Error
	})
}

func (s *Store) CountSigningKeys(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.WithContext(ctx).Model(&signingKeyModel{}).Count(&n).Error
	return n, err
}
