package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/crypto"
)

func (a *Auth) validateNewPassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	if len(newPassword) < 8 {
		return fmt.Errorf("%w: password too short", ErrPasswordPolicy)
	}
	u, err := a.repo.GetUserByID(ctx, userID)
	if err != nil || u == nil {
		return ErrNotFound
	}
	entries, err := a.repo.ListPasswordHistory(ctx, userID, a.cfg.PasswordHistoryN)
	if err != nil {
		return err
	}
	for _, e := range entries {
		ok, err := crypto.VerifyPassword(newPassword, e.PasswordHash)
		if err != nil {
			continue
		}
		if ok {
			return fmt.Errorf("%w: password reused", ErrPasswordPolicy)
		}
	}
	plainKey, err := crypto.DecodeKey32(a.cfg.PasswordHistoryEncryptionKey)
	if err != nil {
		return err
	}
	for _, e := range entries {
		prev, err := crypto.DecryptAESGCM(plainKey, e.Nonce, e.Ciphertext, nil)
		if err != nil {
			continue
		}
		if crypto.Levenshtein(newPassword, string(prev)) <= 2 {
			return fmt.Errorf("%w: too similar to previous password", ErrPasswordPolicy)
		}
	}
	return nil
}

func (a *Auth) appendPasswordHistory(ctx context.Context, userID uuid.UUID, newPassword, newHash string) error {
	plainKey, err := crypto.DecodeKey32(a.cfg.PasswordHistoryEncryptionKey)
	if err != nil {
		return err
	}
	nonce, cipher, err := crypto.EncryptAESGCM(plainKey, []byte(newPassword), nil)
	if err != nil {
		return err
	}
	if err := a.repo.InsertPasswordHistory(ctx, userID, newHash, cipher, nonce); err != nil {
		return err
	}
	return a.repo.TrimPasswordHistory(ctx, userID, a.cfg.PasswordHistoryN)
}

func normalizeLogin(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
