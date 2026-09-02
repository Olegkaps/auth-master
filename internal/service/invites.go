package service

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/crypto"
)

// RegistrationInvitePreview is returned for a valid unused invite (no secrets).
type RegistrationInvitePreview struct {
	Valid            bool
	RegistrationOpen bool
	Email            *string
	Superuser        bool
	ExpiresAt        time.Time
}

func (a *Auth) PreviewRegistrationInvite(ctx context.Context, rawToken string) (*RegistrationInvitePreview, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return &RegistrationInvitePreview{Valid: false, RegistrationOpen: a.cfg.RegistrationOpen}, nil
	}
	inv, err := a.repo.GetValidRegistrationInviteByTokenHash(ctx, hashRefreshToken(rawToken))
	if err != nil {
		return nil, err
	}
	if inv == nil {
		return &RegistrationInvitePreview{Valid: false, RegistrationOpen: a.cfg.RegistrationOpen}, nil
	}
	return &RegistrationInvitePreview{Valid: true, RegistrationOpen: a.cfg.RegistrationOpen, Email: inv.Email, Superuser: inv.Superuser, ExpiresAt: inv.ExpiresAt}, nil
}

// CreateRegistrationInvite returns a one-time raw token (show once). Only superusers may call this.
// When superuser is true, the registered account is granted superuser access.
func (a *Auth) CreateRegistrationInvite(ctx context.Context, adminID uuid.UUID, lockedEmail *string, superuser bool, ttl time.Duration) (rawToken string, expiresAt time.Time, registrationURL string, err error) {
	ttl, err = normalizeInviteTTL(ttl)
	if err != nil {
		return "", time.Time{}, "", err
	}
	ok, err := a.IsSuperuser(ctx, adminID)
	if err != nil {
		return "", time.Time{}, "", err
	}
	if !ok {
		return "", time.Time{}, "", ErrForbidden
	}
	raw, err := crypto.RandomBytes(32)
	if err != nil {
		return "", time.Time{}, "", err
	}
	token := hex.EncodeToString(raw)
	expiresAt = time.Now().Add(ttl)
	_, err = a.repo.InsertRegistrationInvite(ctx, hashRefreshToken(token), lockedEmail, superuser, expiresAt, adminID)
	if err != nil {
		return "", time.Time{}, "", err
	}
	registrationURL, err = oneTimeCallbackURL(a.cfg.RegistrationInviteCallbackURL, strings.TrimRight(a.cfg.RegistrationInviteBaseURL, "/")+"/#/register", token)
	if err != nil {
		return "", time.Time{}, "", err
	}
	return token, expiresAt, registrationURL, nil
}
