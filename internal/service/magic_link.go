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
	"github.com/olegkapshai/auth-master/internal/domain"
)

// StartMagicLink emails a one-time passwordless login link. To avoid account
// enumeration it is a silent no-op for unknown logins or accounts without an
// email — callers should always report success to the client.
func (a *Auth) StartMagicLink(ctx context.Context, login string) error {
	login = normalizeLogin(login)
	u, err := a.repo.GetUserByLogin(ctx, login)
	if err != nil || u == nil || u.Email == nil || u.Kind != domain.UserHuman || u.BannedAt != nil {
		return nil
	}
	raw, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}
	token := hex.EncodeToString(raw)
	exp := time.Now().Add(a.cfg.MagicLinkTTL)
	if _, err := a.repo.InsertMagicLink(ctx, hashRefreshToken(token), u.ID, exp); err != nil {
		return err
	}
	base := strings.TrimRight(a.cfg.RegistrationInviteBaseURL, "/")
	link := fmt.Sprintf("%s/#/magic?token=%s", base, url.QueryEscape(token))
	return a.mail.Send([]string{*u.Email}, "Your login link",
		fmt.Sprintf("Sign in with this one-time link (valid %v):\n\n%s", a.cfg.MagicLinkTTL, link))
}

// CompleteMagicLink verifies a one-time login token and issues a session. It is
// single-factor by design (proof of email possession), an alternative to the
// password + OTP flow.
func (a *Auth) CompleteMagicLink(ctx context.Context, token, deviceID, deviceLabel string) (*TokenPair, *domain.User, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, ErrOTPInvalid
	}
	userID, err := a.repo.ConsumeMagicLink(ctx, hashRefreshToken(token))
	if err != nil {
		return nil, nil, err
	}
	if userID == uuid.Nil {
		return nil, nil, ErrOTPInvalid
	}
	u, err := a.repo.GetUserByID(ctx, userID)
	if err != nil || u == nil {
		return nil, nil, ErrOTPInvalid
	}
	if err := requireActiveUser(u); err != nil {
		return nil, nil, err
	}
	return a.issueTokenPair(ctx, u, deviceID, deviceLabel)
}
