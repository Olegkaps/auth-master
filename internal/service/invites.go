package service

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/crypto"
)

// RegistrationInvitePreview is returned for a valid unused invite (no secrets).
type RegistrationInvitePreview struct {
	Valid     bool
	Email     *string
	Superuser bool
	ExpiresAt time.Time
}

func (a *Auth) PreviewRegistrationInvite(ctx context.Context, rawToken string) (*RegistrationInvitePreview, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return &RegistrationInvitePreview{Valid: false}, nil
	}
	inv, err := a.repo.GetValidRegistrationInviteByTokenHash(ctx, hashRefreshToken(rawToken))
	if err != nil {
		return nil, err
	}
	if inv == nil {
		return &RegistrationInvitePreview{Valid: false}, nil
	}
	return &RegistrationInvitePreview{Valid: true, Email: inv.Email, Superuser: inv.Superuser, ExpiresAt: inv.ExpiresAt}, nil
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
	base := strings.TrimRight(a.cfg.RegistrationInviteBaseURL, "/")
	registrationURL = fmt.Sprintf("%s/#/register?token=%s", base, url.QueryEscape(token))
	return token, expiresAt, registrationURL, nil
}
