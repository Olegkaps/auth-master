package service

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/config"
	"github.com/olegkapshai/auth-master/internal/crypto"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/jwtutil"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/olegkapshai/auth-master/internal/repository"
)

type Auth struct {
	cfg           *config.Config
	repo          repository.Repository
	mail          *mail.Sender
	log           *slog.Logger
	signingMaster []byte
	otpPepper     []byte
}

func NewAuth(cfg *config.Config, repo repository.Repository, m *mail.Sender, log *slog.Logger) (*Auth, error) {
	sm, err := crypto.DecodeKey32(cfg.SigningKeyMasterKey)
	if err != nil {
		return nil, fmt.Errorf("signing master key: %w", err)
	}
	h := make([]byte, 32)
	copy(h, sm) // otp pepper same material
	return &Auth{cfg: cfg, repo: repo, mail: m, log: log, signingMaster: sm, otpPepper: h}, nil
}

func (a *Auth) Register(ctx context.Context, inviteToken, login, email, password string) (uuid.UUID, error) {
	inviteToken = strings.TrimSpace(inviteToken)
	if inviteToken == "" {
		return uuid.Nil, ErrInvalidInvite
	}
	inv, err := a.repo.GetValidRegistrationInviteByTokenHash(ctx, hashRefreshToken(inviteToken))
	if err != nil {
		return uuid.Nil, err
	}
	if inv == nil {
		return uuid.Nil, ErrInvalidInvite
	}
	login = normalizeLogin(login)
	email = strings.TrimSpace(email)
	if inv.Email != nil && strings.TrimSpace(*inv.Email) != "" && !strings.EqualFold(email, *inv.Email) {
		return uuid.Nil, ErrInvalidInvite
	}
	if len(password) < 8 {
		return uuid.Nil, fmt.Errorf("%w: password too short", ErrPasswordPolicy)
	}
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return uuid.Nil, err
	}
	id, err := a.repo.CreateHumanUser(ctx, login, email, hash)
	if err != nil {
		return uuid.Nil, err
	}
	if err := a.appendPasswordHistory(ctx, id, password, hash); err != nil {
		return id, err
	}
	if err := a.repo.MarkRegistrationInviteUsed(ctx, inv.ID); err != nil {
		return id, err
	}
	return id, nil
}

type LoginPasswordResult struct {
	OTPRequired      bool
	PasswordExpired  bool
	LoginChallengeID string // empty; we use email OTP without separate challenge id — client uses login only
}

func (a *Auth) LoginPassword(ctx context.Context, login, password string, ip net.IP) (*LoginPasswordResult, error) {
	login = normalizeLogin(login)
	u, err := a.repo.GetUserByLogin(ctx, login)
	if err != nil {
		return nil, err
	}
	if u == nil || u.Kind != domain.UserHuman {
		a.recordFailedLogin(ctx, login, ip)
		return nil, ErrInvalidCredentials
	}
	if u.LockedUntil != nil && time.Now().Before(*u.LockedUntil) {
		return nil, ErrLocked
	}
	if u.PasswordHash == nil {
		a.recordFailedLogin(ctx, login, ip)
		return nil, ErrInvalidCredentials
	}
	ok, err := crypto.VerifyPassword(password, *u.PasswordHash)
	if err != nil || !ok {
		a.recordFailedLogin(ctx, login, ip)
		return nil, ErrInvalidCredentials
	}
	if a.passwordExpired(u) {
		return &LoginPasswordResult{PasswordExpired: true}, nil
	}
	code, err := randomNumericCode(a.cfg.OTPCodeLength)
	if err != nil {
		return nil, err
	}
	chash := hashOTP(a.otpPepper, code)
	exp := time.Now().Add(a.cfg.OTPCodeTTL)
	if _, err := a.repo.CreateEmailOTP(ctx, u.ID, domain.OTPLogin, chash, exp, nil); err != nil {
		return nil, err
	}
	if u.Email != nil {
		_ = a.mail.Send([]string{*u.Email}, "Your login code", fmt.Sprintf("Code: %s (expires in %v)", code, a.cfg.OTPCodeTTL))
	}
	return &LoginPasswordResult{OTPRequired: true}, nil
}

func (a *Auth) passwordExpired(u *domain.User) bool {
	if u.PasswordChangedAt == nil || a.cfg.PasswordMaxAge <= 0 {
		return false
	}
	return time.Since(*u.PasswordChangedAt) > a.cfg.PasswordMaxAge
}

func (a *Auth) recordFailedLogin(ctx context.Context, login string, ip net.IP) {
	_ = a.repo.InsertFailedLogin(ctx, login, ip)
	since := time.Now().Add(-a.cfg.LoginFailWindow)
	n, _ := a.repo.CountFailedLogins(ctx, login, since)
	if int(n) >= a.cfg.LoginFailMax {
		lock := time.Now().Add(a.cfg.LoginLockDuration)
		u, _ := a.repo.GetUserByLogin(ctx, login)
		if u != nil {
			_ = a.repo.SetLockedUntil(ctx, u.ID, &lock)
		}
	}
	if int(n) == a.cfg.NotifyOnFailThreshold && a.cfg.NotifyOnFailThreshold > 0 {
		u, _ := a.repo.GetUserByLogin(ctx, login)
		if u != nil && u.Email != nil {
			_ = a.mail.Send([]string{*u.Email}, "Security alert", fmt.Sprintf("Multiple failed sign-in attempts for %s", login))
		}
	}
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

func (a *Auth) LoginVerifyOTP(ctx context.Context, login, code, deviceID, deviceLabel string) (*TokenPair, *domain.User, error) {
	login = normalizeLogin(login)
	u, err := a.repo.GetUserByLogin(ctx, login)
	if err != nil || u == nil {
		return nil, nil, ErrOTPInvalid
	}
	row, err := a.repo.GetLatestOTP(ctx, u.ID, domain.OTPLogin)
	if err != nil || row == nil {
		return nil, nil, ErrOTPInvalid
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, nil, ErrOTPInvalid
	}
	if !otpCodesEqual(a.otpPepper, code, row.CodeHash) {
		_ = a.repo.IncrementOTPAttempt(ctx, row.ID)
		return nil, nil, ErrOTPInvalid
	}
	if err := a.repo.ConsumeOTP(ctx, row.ID); err != nil {
		return nil, nil, ErrOTPInvalid
	}
	return a.issueTokenPair(ctx, u, deviceID, deviceLabel)
}

func (a *Auth) issueTokenPair(ctx context.Context, u *domain.User, deviceID, deviceLabel string) (*TokenPair, *domain.User, error) {
	if err := a.ensureSigningBootstrap(ctx); err != nil {
		return nil, nil, err
	}
	for {
		n, err := a.repo.CountActiveRefreshSessions(ctx, u.ID)
		if err != nil {
			return nil, nil, err
		}
		if int(n) < a.cfg.MaxSessionsPerUser {
			break
		}
		if err := a.repo.DeleteOldestRefreshSession(ctx, u.ID); err != nil {
			return nil, nil, err
		}
	}
	rawRefresh, err := randomRefreshToken()
	if err != nil {
		return nil, nil, err
	}
	th := hashRefreshToken(rawRefresh)
	exp := time.Now().Add(a.cfg.RefreshTokenTTL)
	if _, err := a.repo.UpsertRefreshSession(ctx, u.ID, deviceID, deviceLabel, th, exp); err != nil {
		return nil, nil, err
	}
	kid, sec, err := a.currentSigningSecret(ctx)
	if err != nil {
		return nil, nil, err
	}
	access, err := jwtutil.SignAccess(sec, kid, u.ID.String(), u.Login, jwtutil.TypeAccess, a.cfg.AccessTokenTTL)
	if err != nil {
		return nil, nil, err
	}
	_ = a.mail.Send([]string{*u.Email}, "New sign-in", fmt.Sprintf("Account %s signed in from device %s", u.Login, deviceID))
	return &TokenPair{AccessToken: access, RefreshToken: rawRefresh, ExpiresAt: time.Now().Add(a.cfg.AccessTokenTTL)}, u, nil
}

func (a *Auth) Refresh(ctx context.Context, refreshToken, deviceID, deviceLabel string) (*TokenPair, error) {
	th := hashRefreshToken(refreshToken)
	row, err := a.repo.FindRefreshByTokenHash(ctx, th)
	if err != nil || row == nil {
		return nil, ErrInvalidCredentials
	}
	if row.RevokedAt != nil || time.Now().After(row.ExpiresAt) {
		return nil, ErrInvalidCredentials
	}
	u, err := a.repo.GetUserByID(ctx, row.UserID)
	if err != nil || u == nil {
		return nil, ErrInvalidCredentials
	}
	if err := a.ensureSigningBootstrap(ctx); err != nil {
		return nil, err
	}
	newRaw, err := randomRefreshToken()
	if err != nil {
		return nil, err
	}
	newHash := hashRefreshToken(newRaw)
	exp := time.Now().Add(a.cfg.RefreshTokenTTL)
	if err := a.repo.ReplaceRefreshToken(ctx, row.ID, th, newHash, exp); err != nil {
		return nil, ErrInvalidCredentials
	}
	kid, sec, err := a.currentSigningSecret(ctx)
	if err != nil {
		return nil, err
	}
	access, err := jwtutil.SignAccess(sec, kid, u.ID.String(), u.Login, jwtutil.TypeAccess, a.cfg.AccessTokenTTL)
	if err != nil {
		return nil, err
	}
	return &TokenPair{AccessToken: access, RefreshToken: newRaw, ExpiresAt: time.Now().Add(a.cfg.AccessTokenTTL)}, nil
}

func (a *Auth) Logout(ctx context.Context, refreshToken string) error {
	th := hashRefreshToken(refreshToken)
	row, err := a.repo.FindRefreshByTokenHash(ctx, th)
	if err != nil || row == nil {
		return nil
	}
	return a.repo.RevokeRefreshSession(ctx, row.ID)
}

func (a *Auth) VerifyAccessToken(ctx context.Context, token string, wantTyp string) (*jwtutil.Claims, error) {
	claims, err := jwtutil.ParseUnverifiedClaims(token)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	sec, _, stale, err := a.secretForKID(ctx, claims.Kid, now)
	if err != nil {
		return nil, err
	}
	if stale {
		return nil, ErrStaleSigningKey
	}
	v, err := jwtutil.ParseAndVerify(token, sec)
	if err != nil {
		return nil, err
	}
	if v.Typ != wantTyp {
		return nil, ErrWrongTokenType
	}
	return v, nil
}

// VerifyAccessOrServiceToken validates JWT after signature check; typ must be access or service.
func (a *Auth) VerifyAccessOrServiceToken(ctx context.Context, token string) (*jwtutil.Claims, error) {
	uv, err := jwtutil.ParseUnverifiedClaims(token)
	if err != nil {
		return nil, err
	}
	if uv.Typ != jwtutil.TypeAccess && uv.Typ != jwtutil.TypeService {
		return nil, ErrWrongTokenType
	}
	now := time.Now()
	sec, _, stale, err := a.secretForKID(ctx, uv.Kid, now)
	if err != nil {
		return nil, err
	}
	if stale {
		return nil, ErrStaleSigningKey
	}
	v, err := jwtutil.ParseAndVerify(token, sec)
	if err != nil {
		return nil, err
	}
	if v.Typ != jwtutil.TypeAccess && v.Typ != jwtutil.TypeService {
		return nil, ErrWrongTokenType
	}
	return v, nil
}

func (a *Auth) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	u, err := a.repo.GetUserByID(ctx, userID)
	if err != nil || u == nil || u.PasswordHash == nil {
		return ErrNotFound
	}
	ok, err := crypto.VerifyPassword(oldPassword, *u.PasswordHash)
	if err != nil || !ok {
		return ErrInvalidCredentials
	}
	if err := a.validateNewPassword(ctx, userID, newPassword); err != nil {
		return err
	}
	nhash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := a.repo.UpdatePassword(ctx, userID, nhash); err != nil {
		return err
	}
	if err := a.appendPasswordHistory(ctx, userID, newPassword, nhash); err != nil {
		return err
	}
	if u.Email != nil {
		_ = a.mail.Send([]string{*u.Email}, "Password changed", "Your password was changed.")
	}
	return nil
}

func (a *Auth) IssueServiceToken(ctx context.Context, login, secret string) (string, time.Time, error) {
	login = normalizeLogin(login)
	u, err := a.repo.GetUserByLogin(ctx, login)
	if err != nil || u == nil || u.Kind != domain.UserService || u.ServiceSecretHash == nil {
		return "", time.Time{}, ErrInvalidCredentials
	}
	ok, err := crypto.VerifySecret(secret, *u.ServiceSecretHash)
	if err != nil || !ok {
		return "", time.Time{}, ErrInvalidCredentials
	}
	if err := a.ensureSigningBootstrap(ctx); err != nil {
		return "", time.Time{}, err
	}
	kid, sec, err := a.currentSigningSecret(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	exp := time.Now().Add(a.cfg.AccessTokenTTL)
	tok, err := jwtutil.SignAccess(sec, kid, u.ID.String(), u.Login, jwtutil.TypeService, a.cfg.AccessTokenTTL)
	if err != nil {
		return "", time.Time{}, err
	}
	return tok, exp, nil
}

func (a *Auth) StartSessionRevokeOTP(ctx context.Context, userID uuid.UUID) error {
	u, err := a.repo.GetUserByID(ctx, userID)
	if err != nil || u == nil || u.Email == nil {
		return ErrNotFound
	}
	code, err := randomNumericCode(a.cfg.OTPCodeLength)
	if err != nil {
		return err
	}
	chash := hashOTP(a.otpPepper, code)
	exp := time.Now().Add(a.cfg.OTPCodeTTL)
	if _, err := a.repo.CreateEmailOTP(ctx, userID, domain.OTPSessionRevoke, chash, exp, nil); err != nil {
		return err
	}
	return a.mail.Send([]string{*u.Email}, "Confirm session revoke", fmt.Sprintf("Code: %s", code))
}

func (a *Auth) RevokeSessionWithOTP(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID, code string) error {
	row, err := a.repo.GetLatestOTP(ctx, userID, domain.OTPSessionRevoke)
	if err != nil || row == nil || time.Now().After(row.ExpiresAt) {
		return ErrOTPInvalid
	}
	if !otpCodesEqual(a.otpPepper, code, row.CodeHash) {
		_ = a.repo.IncrementOTPAttempt(ctx, row.ID)
		return ErrOTPInvalid
	}
	if err := a.repo.ConsumeOTP(ctx, row.ID); err != nil {
		return ErrOTPInvalid
	}
	sess, err := a.repo.GetRefreshByID(ctx, sessionID)
	if err != nil || sess == nil || sess.UserID != userID {
		return ErrNotFound
	}
	return a.repo.RevokeRefreshSession(ctx, sessionID)
}

// BeginStepUp2FA creates a correlation id, DB session, and emails an OTP code.
func (a *Auth) BeginStepUp2FA(ctx context.Context, userID uuid.UUID, ttl time.Duration) (correlationID string, err error) {
	u, err := a.repo.GetUserByID(ctx, userID)
	if err != nil || u == nil || u.Email == nil {
		return "", ErrNotFound
	}
	correlationID = uuid.New().String()
	exp := time.Now().Add(ttl)
	if err := a.repo.CreateStepUp2FASession(ctx, correlationID, userID, exp); err != nil {
		return "", err
	}
	code, err := randomNumericCode(a.cfg.OTPCodeLength)
	if err != nil {
		return "", err
	}
	chash := hashOTP(a.otpPepper, code)
	otpExp := time.Now().Add(a.cfg.OTPCodeTTL)
	if ttl < a.cfg.OTPCodeTTL {
		otpExp = time.Now().Add(ttl)
	}
	if _, err := a.repo.CreateEmailOTP(ctx, userID, domain.OTPStepUp2FA, chash, otpExp, &correlationID); err != nil {
		return "", err
	}
	_ = a.mail.Send([]string{*u.Email}, "Step-up 2FA code", fmt.Sprintf("Code: %s\nCorrelation: %s", code, correlationID))
	return correlationID, nil
}

// CompleteStepUp2FAOTP validates OTP and marks the step-up session approved.
func (a *Auth) CompleteStepUp2FAOTP(ctx context.Context, correlationID, code string) error {
	row, err := a.repo.GetOTPByCorrelation(ctx, correlationID)
	if err != nil || row == nil || time.Now().After(row.ExpiresAt) {
		return ErrOTPInvalid
	}
	if !otpCodesEqual(a.otpPepper, code, row.CodeHash) {
		_ = a.repo.IncrementOTPAttempt(ctx, row.ID)
		return ErrOTPInvalid
	}
	if err := a.repo.ConsumeOTP(ctx, row.ID); err != nil {
		return ErrOTPInvalid
	}
	return a.repo.ApproveStepUp2FA(ctx, correlationID)
}

// StepUp2FAStatusForUser returns session status only if it belongs to userID.
func (a *Auth) StepUp2FAStatusForUser(ctx context.Context, correlationID string, userID uuid.UUID) (string, error) {
	s, err := a.repo.GetStepUp2FA(ctx, correlationID)
	if err != nil || s == nil || s.UserID != userID {
		return "", ErrNotFound
	}
	if s.Status == "pending" && time.Now().After(s.ExpiresAt) {
		_ = a.repo.ExpireStepUp2FA(ctx, correlationID)
		return "expired", nil
	}
	return s.Status, nil
}

// ExpireStepUp2FASessionForUser expires a session only if owned by userID.
func (a *Auth) ExpireStepUp2FASessionForUser(ctx context.Context, correlationID string, userID uuid.UUID) error {
	s, err := a.repo.GetStepUp2FA(ctx, correlationID)
	if err != nil || s == nil || s.UserID != userID {
		return ErrNotFound
	}
	return a.repo.ExpireStepUp2FA(ctx, correlationID)
}
