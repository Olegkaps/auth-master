package service

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
)

// StartMagicLink emails a one-time passwordless login link. After basic input
// validation, every identity and operational outcome is deliberately public
// success: callers must not be able to distinguish an unknown or ineligible
// identity from database, configuration, randomness, or delivery failures.
func (a *Auth) StartMagicLink(ctx context.Context, login string) error {
	_ = ctx
	login, err := normalizePublicIdentity(login)
	if err != nil {
		return err
	}
	a.publicMail.enqueue(publicMailJob{kind: publicMailMagicLink, identity: login})
	return nil
}

func (a *Auth) processMagicLink(ctx context.Context, login string) {
	u, err := a.repo.GetHumanUserByLoginOrEmail(ctx, login)
	if err != nil {
		a.logMagicLinkSuppression("identity_lookup")
		return
	}
	if u == nil || u.Email == nil || u.Kind != domain.UserHuman || u.BannedAt != nil {
		a.logMagicLinkSuppression("identity_ineligible")
		return
	}
	raw, err := a.randomBytes(32)
	if err != nil {
		a.logMagicLinkSuppression("token_generation")
		return
	}
	token := hex.EncodeToString(raw)
	link, err := oneTimeCallbackURL(a.cfg.MagicLinkCallbackURL, strings.TrimRight(a.cfg.RegistrationInviteBaseURL, "/")+"/#/magic", token)
	if err != nil {
		a.logMagicLinkSuppression("callback_configuration")
		return
	}
	exp := time.Now().Add(a.cfg.MagicLinkTTL)
	linkID, err := a.repo.InsertMagicLink(ctx, hashRefreshToken(token), u.ID, exp)
	if err != nil {
		a.logMagicLinkSuppression("token_persistence")
		return
	}
	if err := a.mail.Send(ctx, []string{*u.Email}, "Your login link",
		fmt.Sprintf("Sign in with this one-time link (valid %v):\n\n%s", a.cfg.MagicLinkTTL, link)); err != nil {
		a.invalidateUndeliveredMagicLink(ctx, linkID)
		a.logMagicLinkSuppression("message_delivery")
		return
	}
}

func (a *Auth) invalidateUndeliveredMagicLink(ctx context.Context, id uuid.UUID) {
	// SMTP commonly returns because the mail-job context has already expired.
	// Cleanup is a compensating security write and must therefore not inherit
	// cancellation from that context. Preserve request values, but give the
	// detached operation a small independent bound so shutdown cannot hang.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		if err := a.repo.InvalidateMagicLink(cleanupCtx, id); err == nil {
			return
		}
		if cleanupCtx.Err() != nil {
			break
		}
	}
	a.logMagicLinkSuppression("token_invalidation")
}

func (a *Auth) logMagicLinkSuppression(operation string) {
	if a.log != nil {
		a.log.Warn("magic link request suppressed", "operation", operation)
	}
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
