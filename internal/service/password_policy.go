package service

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/crypto"
)

// checkPasswordComplexity enforces length plus at least one lowercase letter,
// one uppercase letter, one digit, and one special (non-alphanumeric) character.
func checkPasswordComplexity(pw string) error {
	if len(pw) < 8 {
		return fmt.Errorf("%w: password too short (min 8 characters)", ErrPasswordPolicy)
	}
	var hasLower, hasUpper, hasDigit, hasSpecial bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsSpace(r):
			// spaces don't count toward the special-character requirement
		default:
			hasSpecial = true
		}
	}
	var missing []string
	if !hasLower {
		missing = append(missing, "lowercase letter")
	}
	if !hasUpper {
		missing = append(missing, "uppercase letter")
	}
	if !hasDigit {
		missing = append(missing, "digit")
	}
	if !hasSpecial {
		missing = append(missing, "special character")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: password must contain at least one %s", ErrPasswordPolicy, strings.Join(missing, ", "))
	}
	return nil
}

func (a *Auth) validateNewPassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	if err := checkPasswordComplexity(newPassword); err != nil {
		return err
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
