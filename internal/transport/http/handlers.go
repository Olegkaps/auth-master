package httptransport

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/service"
)

type regBody struct {
	InviteToken string `json:"invite_token"`
	Login       string `json:"login"`
	Email       string `json:"email"`
	Password    string `json:"password"`
}

// handleRegister registers a human user using a one-time invite token.
// @Summary Register human user
// @Description Creates an account; invite must be valid and may lock the registration email.
// @Tags auth
// @Accept json
// @Produce json
// @Param body body RegisterRequestBody true "Registration payload"
// @Success 201 {object} RegisterCreatedResponse
// @Failure 400 {object} ErrEnvelope "Invalid JSON, password policy, duplicate login/email, …"
// @Failure 410 {object} ErrEnvelope "Invalid or expired invite"
// @Router /v1/auth/register [post]
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var b regBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if b.InviteToken == "" {
		s.writeErr(w, http.StatusBadRequest, "invite_token required")
		return
	}
	id, err := s.auth.Register(r.Context(), b.InviteToken, b.Login, b.Email, b.Password)
	if err != nil {
		if errors.Is(err, service.ErrInvalidInvite) {
			s.writeErr(w, http.StatusGone, "invalid or expired invite")
			return
		}
		if errors.Is(err, service.ErrPasswordPolicy) {
			s.writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]string{"user_id": id.String()})
}

// handleRegistrationInvitePreview validates an invite token without consuming it.
// @Summary Preview registration invite
// @Tags auth
// @Produce json
// @Param token query string true "Raw invite token"
// @Success 200 {object} RegistrationInvitePreviewResponse
// @Failure 500 {object} ErrEnvelope
// @Router /v1/auth/registration-invite [get]
func (s *Server) handleRegistrationInvitePreview(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	prev, err := s.auth.PreviewRegistrationInvite(r.Context(), tok)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]any{"valid": prev.Valid}
	if prev.Valid {
		out["email"] = prev.Email
		out["superuser"] = prev.Superuser
		out["expires_at"] = prev.ExpiresAt.UTC().Format(time.RFC3339)
	}
	s.writeJSON(w, http.StatusOK, out)
}

type createInviteBody struct {
	Email      string `json:"email"`
	TTLSeconds int64  `json:"ttl_seconds"`
	Superuser  bool   `json:"superuser"`
}

// handleCreateRegistrationInvite creates a new registration invite (superuser only).
// @Summary Create registration invite
// @Tags admin
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Param body body CreateRegistrationInviteRequest true "Optional locked email and TTL"
// @Success 201 {object} CreateRegistrationInviteResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope "Not a superuser"
// @Failure 401 {object} ErrEnvelope
// @Router /v1/admin/registration-invites [post]
func (s *Server) handleCreateRegistrationInvite(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	var b createInviteBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	ttl, err := service.DurationFromSeconds(b.TTLSeconds)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var locked *string
	if e := strings.TrimSpace(b.Email); e != "" {
		locked = &e
	}
	raw, exp, regURL, err := s.auth.CreateRegistrationInvite(r.Context(), uid, locked, b.Superuser, ttl)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "superuser only")
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"token":            raw,
		"expires_at":       exp.UTC().Format(time.RFC3339),
		"registration_url": regURL,
	})
}

type createServiceAccountBody struct {
	Login     string `json:"login"`
	Secret    string `json:"secret"`
	Superuser bool   `json:"superuser"`
}

// handleCreateServiceAccount creates a service principal and returns its ID.
// The raw secret is accepted only in this request and is never returned.
// @Summary Create service account
// @Tags admin
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Param body body CreateServiceAccountRequest true "Service account credentials and privilege"
// @Success 201 {object} CreateServiceAccountResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/admin/service-accounts [post]
func (s *Server) handleCreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserID(r.Context())
	var body createServiceAccountBody
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	id, err := s.auth.CreateServiceAccount(r.Context(), actor, body.Login, body.Secret, body.Superuser)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden), errors.Is(err, service.ErrBanned):
			s.writeErr(w, http.StatusForbidden, "superuser only")
		case errors.Is(err, service.ErrInvalidArgument), errors.Is(err, service.ErrPasswordPolicy):
			s.writeErr(w, http.StatusBadRequest, err.Error())
		default:
			s.writeErr(w, http.StatusInternalServerError, "service account creation failed")
		}
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]string{"user_id": id.String()})
}

type loginBody struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// handleLogin performs password authentication and triggers email OTP when required.
// @Summary Login (password step)
// @Tags auth
// @Accept json
// @Produce json
// @Param body body LoginRequestBody true "Credentials"
// @Success 200 {object} LoginOTPResponse "otp_sent indicates whether OTP email was sent"
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope "Invalid credentials"
// @Failure 403 {object} LoginPasswordExpiredResponse "Password must be changed"
// @Failure 423 {object} ErrEnvelope "Account locked"
// @Failure 500 {object} ErrEnvelope
// @Router /v1/auth/login [post]
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var b loginBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	res, err := s.auth.LoginPassword(r.Context(), b.Login, b.Password, clientIP(r))
	if err != nil {
		if errors.Is(err, service.ErrBanned) {
			s.writeErr(w, http.StatusForbidden, "account banned")
			return
		}
		if errors.Is(err, service.ErrInvalidCredentials) {
			s.writeErr(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if errors.Is(err, service.ErrLocked) {
			s.writeErr(w, http.StatusLocked, "account locked")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if res.PasswordExpired {
		s.writeJSON(w, http.StatusForbidden, map[string]any{"password_expired": true})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"otp_sent": res.OTPRequired, "login_challenge": res.LoginChallenge})
}

type verifyBody struct {
	Challenge   string `json:"challenge"`
	Code        string `json:"code"`
	DeviceID    string `json:"device_id"`
	DeviceLabel string `json:"device_label"`
}

// handleLoginVerify completes login with OTP; sets HttpOnly refresh cookie and csrf_token cookie.
// @Summary Verify login OTP
// @Tags auth
// @Accept json
// @Produce json
// @Param body body LoginVerifyRequestBody true "OTP and device binding"
// @Success 200 {object} TokenPairResponse "Includes csrf_token for subsequent CSRF-protected calls"
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope "Invalid OTP"
// @Failure 500 {object} ErrEnvelope
// @Router /v1/auth/login/verify-otp [post]
func (s *Server) handleLoginVerify(w http.ResponseWriter, r *http.Request) {
	var b verifyBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if b.DeviceID == "" {
		s.writeErr(w, http.StatusBadRequest, "device_id required")
		return
	}
	if b.Challenge == "" {
		s.writeErr(w, http.StatusBadRequest, "challenge required")
		return
	}
	tokens, _, err := s.auth.LoginVerifyOTP(r.Context(), b.Challenge, b.Code, b.DeviceID, b.DeviceLabel)
	if err != nil {
		if errors.Is(err, service.ErrBanned) {
			s.writeErr(w, http.StatusForbidden, "account banned")
			return
		}
		if errors.Is(err, service.ErrOTPInvalid) {
			s.writeErr(w, http.StatusUnauthorized, "invalid otp")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	csrf, _ := uuid.NewRandom()
	s.setCSRFCookie(w, csrf.String())
	maxAge := int(s.cfg.RefreshTokenTTL.Seconds())
	s.setRefreshCookie(w, tokens.RefreshToken, maxAge)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  tokens.AccessToken,
		"expires_at":    tokens.ExpiresAt.UTC().Format(time.RFC3339),
		"csrf_token":    csrf.String(),
		"refresh_token": tokens.RefreshToken,
	})
}

type magicStartBody struct {
	Login string `json:"login"`
}

// handleMagicLinkStart emails a one-time passwordless login link.
// @Summary Request a magic login link
// @Description Public passwordless flow. Always returns 200 to avoid enumeration; a link is emailed only when the login exists and has an email.
// @Tags auth
// @Accept json
// @Produce json
// @Param body body MagicLinkStartRequest true "Login to send a link to"
// @Success 200 {object} MagicLinkStartResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/auth/login/magic-link [post]
func (s *Server) handleMagicLinkStart(w http.ResponseWriter, r *http.Request) {
	var b magicStartBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(b.Login) == "" {
		s.writeErr(w, http.StatusBadRequest, "login required")
		return
	}
	if err := s.auth.StartMagicLink(r.Context(), b.Login); err != nil {
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "link_sent"})
}

type magicVerifyBody struct {
	Token       string `json:"token"`
	DeviceID    string `json:"device_id"`
	DeviceLabel string `json:"device_label"`
}

// handleMagicLinkVerify completes a passwordless login; sets refresh + csrf cookies.
// @Summary Complete magic-link login
// @Tags auth
// @Accept json
// @Produce json
// @Param body body MagicLinkVerifyRequest true "One-time token and device binding"
// @Success 200 {object} TokenPairResponse "Includes csrf_token"
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope "Invalid or expired link"
// @Failure 500 {object} ErrEnvelope
// @Router /v1/auth/login/magic-link/verify [post]
func (s *Server) handleMagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	var b magicVerifyBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if b.DeviceID == "" {
		s.writeErr(w, http.StatusBadRequest, "device_id required")
		return
	}
	tokens, _, err := s.auth.CompleteMagicLink(r.Context(), b.Token, b.DeviceID, b.DeviceLabel)
	if err != nil {
		if errors.Is(err, service.ErrBanned) {
			s.writeErr(w, http.StatusForbidden, "account banned")
			return
		}
		if errors.Is(err, service.ErrOTPInvalid) {
			s.writeErr(w, http.StatusUnauthorized, "invalid or expired link")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	csrf, _ := uuid.NewRandom()
	s.setCSRFCookie(w, csrf.String())
	maxAge := int(s.cfg.RefreshTokenTTL.Seconds())
	s.setRefreshCookie(w, tokens.RefreshToken, maxAge)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  tokens.AccessToken,
		"expires_at":    tokens.ExpiresAt.UTC().Format(time.RFC3339),
		"csrf_token":    csrf.String(),
		"refresh_token": tokens.RefreshToken,
	})
}

// handleRefresh rotates a body-supplied non-ambient refresh token, or falls
// back to the ambient refresh cookie with double-submit CSRF validation.
// @Summary Refresh access token
// @Description Supply refresh_token in JSON for non-ambient body-token mode; that request requires no cookie or CSRF. If refresh_token is omitted, the HttpOnly refresh cookie is required together with X-CSRF-Token matching the csrf_token cookie.
// @Tags auth
// @Accept json
// @Produce json
// @Param X-CSRF-Token header string false "Required only in cookie mode; must match csrf_token cookie"
// @Param body body RefreshRequestBody false "Optional device metadata and non-ambient refresh_token; omitting refresh_token selects cookie mode"
// @Success 200 {object} TokenPairResponse
// @Failure 401 {object} ErrEnvelope "Missing or invalid refresh credential"
// @Failure 403 {object} ErrEnvelope "Cookie-mode CSRF validation failed"
// @Router /v1/auth/refresh [post]
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceID     string `json:"device_id"`
		DeviceLabel  string `json:"device_label"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	// Two auth modes:
	//   - refresh_token in the body: a non-ambient credential (multi-account
	//     client that stores tokens per account) — no CSRF needed.
	//   - HttpOnly cookie: ambient, so require the CSRF double-submit check.
	token := strings.TrimSpace(body.RefreshToken)
	if token == "" {
		c, err := r.Cookie(s.cfg.RefreshCookieName)
		if err != nil || c == nil || c.Value == "" {
			s.writeErr(w, http.StatusUnauthorized, "missing refresh token")
			return
		}
		if !s.csrfOK(r) {
			s.writeErr(w, http.StatusForbidden, "csrf validation failed")
			return
		}
		token = c.Value
	}
	tokens, err := s.auth.Refresh(r.Context(), token, body.DeviceID, body.DeviceLabel)
	if err != nil {
		s.writeErr(w, http.StatusUnauthorized, "refresh failed")
		return
	}
	maxAge := int(s.cfg.RefreshTokenTTL.Seconds())
	s.setRefreshCookie(w, tokens.RefreshToken, maxAge)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  tokens.AccessToken,
		"expires_at":    tokens.ExpiresAt.UTC().Format(time.RFC3339),
		"refresh_token": tokens.RefreshToken,
	})
}

// handleLogout revokes a refresh session and clears the cookie.
// @Summary Logout
// @Description Revokes the session named by refresh_token in the body (multi-account, non-ambient) or, if absent, the HttpOnly cookie session (requires X-CSRF-Token).
// @Tags auth
// @Param X-CSRF-Token header string false "Required only for the cookie path"
// @Param body body LogoutRequest false "Optional refresh_token to revoke a specific account"
// @Success 204 "No content"
// @Failure 403 {object} ErrEnvelope "CSRF validation failed"
// @Router /v1/auth/logout [post]
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if t := strings.TrimSpace(body.RefreshToken); t != "" {
		_ = s.auth.Logout(r.Context(), t) // non-ambient credential, no CSRF needed
	} else {
		if !s.csrfOK(r) {
			s.writeErr(w, http.StatusForbidden, "csrf validation failed")
			return
		}
		if c, err := r.Cookie(s.cfg.RefreshCookieName); err == nil && c != nil {
			_ = s.auth.Logout(r.Context(), c.Value)
		}
	}
	s.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

type stepUp2faBody struct {
	CorrelationID string `json:"correlation_id"`
	Code          string `json:"code"`
}

// handleStepUp2FAComplete completes step-up 2FA with an email OTP (public, correlation-bound).
// @Summary Complete step-up 2FA OTP
// @Tags auth
// @Accept json
// @Produce json
// @Param body body StepUp2FACompleteRequest true "Correlation id and OTP code"
// @Success 200 {object} StepUp2FAOKResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope "Invalid OTP"
// @Router /v1/auth/step-up-2fa/complete [post]
func (s *Server) handleStepUp2FAComplete(w http.ResponseWriter, r *http.Request) {
	var b stepUp2faBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.auth.CompleteStepUp2FAOTP(r.Context(), b.CorrelationID, b.Code); err != nil {
		s.writeErr(w, http.StatusUnauthorized, "invalid otp")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleMe returns the current user profile.
// @Summary Current user
// @Tags me
// @Security BearerAuth
// @Produce json
// @Success 200 {object} MeResponse
// @Failure 401 {object} ErrEnvelope
// @Failure 404 {object} ErrEnvelope
// @Router /v1/me [get]
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	uid, ok := UserID(r.Context())
	if !ok {
		s.writeErr(w, http.StatusUnauthorized, "no user")
		return
	}
	u, err := s.auth.CurrentUser(r.Context(), uid)
	if err != nil {
		s.writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"id":        u.ID.String(),
		"login":     u.Login,
		"email":     u.Email,
		"kind":      u.Kind,
		"superuser": u.Superuser,
	})
}

type pwdBody struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
	Code        string `json:"code"`
}

// handleChangePassword2FAStart emails the OTP required to change the password.
// @Summary Start password change 2FA
// @Description Emails a one-time code that must be supplied to POST /v1/auth/password.
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} StatusResponse
// @Failure 404 {object} ErrEnvelope
// @Router /v1/auth/password/2fa [post]
func (s *Server) handleChangePassword2FAStart(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	if err := s.auth.StartPasswordChange2FA(r.Context(), uid); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			s.writeErr(w, http.StatusNotFound, "user not found")
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "otp_sent"})
}

// handleChangePassword changes password for the authenticated user (requires 2FA).
// @Summary Change password
// @Description Requires the old password AND the email OTP from POST /v1/auth/password/2fa.
// @Tags auth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body ChangePasswordRequestBody true "Old/new password and 2FA code"
// @Success 204 "No content"
// @Failure 400 {object} ErrEnvelope "Password policy or validation"
// @Failure 401 {object} ErrEnvelope "Invalid old password or 2FA code"
// @Failure 404 {object} ErrEnvelope
// @Router /v1/auth/password [post]
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	var b pwdBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	err := s.auth.ChangePassword(r.Context(), uid, b.OldPassword, b.NewPassword, b.Code)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			s.writeErr(w, http.StatusUnauthorized, "invalid old password")
			return
		}
		if errors.Is(err, service.ErrOTPInvalid) {
			s.writeErr(w, http.StatusUnauthorized, "invalid 2fa code")
			return
		}
		if errors.Is(err, service.ErrNotFound) {
			s.writeErr(w, http.StatusNotFound, "user not found")
			return
		}
		if errors.Is(err, service.ErrPasswordPolicy) {
			s.writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type resetStartBody struct {
	Login string `json:"login"`
}

// handlePasswordResetStart emails a password-reset OTP to an unauthenticated user.
// @Summary Start password reset (OTP)
// @Description Public forgot/expired-password flow. Always returns 200 to avoid account enumeration; an email is sent only when the login exists and has an email.
// @Tags auth
// @Accept json
// @Produce json
// @Param body body PasswordResetStartRequest true "Login to reset"
// @Success 200 {object} PasswordResetStartResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/auth/password/reset/start [post]
func (s *Server) handlePasswordResetStart(w http.ResponseWriter, r *http.Request) {
	var b resetStartBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(b.Login) == "" {
		s.writeErr(w, http.StatusBadRequest, "login required")
		return
	}
	if err := s.auth.StartPasswordReset(r.Context(), b.Login); err != nil {
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "otp_sent"})
}

type resetCompleteBody struct {
	Login       string `json:"login"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

// handlePasswordResetComplete sets a new password using the emailed OTP (no old password).
// @Summary Complete password reset (OTP)
// @Tags auth
// @Accept json
// @Produce json
// @Param body body PasswordResetCompleteRequest true "Login, OTP code and new password"
// @Success 204 "No content"
// @Failure 400 {object} ErrEnvelope "Password policy or validation"
// @Failure 401 {object} ErrEnvelope "Invalid or expired OTP"
// @Router /v1/auth/password/reset/complete [post]
func (s *Server) handlePasswordResetComplete(w http.ResponseWriter, r *http.Request) {
	var b resetCompleteBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	err := s.auth.ResetPasswordWithOTP(r.Context(), b.Login, b.Code, b.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrOTPInvalid) {
			s.writeErr(w, http.StatusUnauthorized, "invalid otp")
			return
		}
		if errors.Is(err, service.ErrPasswordPolicy) {
			s.writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListSessions lists refresh sessions for the current user.
// @Summary List refresh sessions
// @Tags sessions
// @Security BearerAuth
// @Produce json
// @Success 200 {object} SessionsListResponse
// @Failure 500 {object} ErrEnvelope
// @Router /v1/sessions [get]
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	list, err := s.auth.Sessions(r.Context(), uid)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	type row struct {
		ID          string  `json:"id"`
		DeviceID    string  `json:"device_id"`
		DeviceLabel *string `json:"device_label,omitempty"`
		CreatedAt   string  `json:"created_at"`
		ExpiresAt   string  `json:"expires_at"`
		Revoked     bool    `json:"revoked"`
	}
	out := make([]row, 0, len(list))
	for _, x := range list {
		out = append(out, row{
			ID:          x.ID.String(),
			DeviceID:    x.DeviceID,
			DeviceLabel: x.DeviceLabel,
			CreatedAt:   x.CreatedAt.UTC().Format(time.RFC3339),
			ExpiresAt:   x.ExpiresAt.UTC().Format(time.RFC3339),
			Revoked:     x.RevokedAt != nil,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// handleSessionRevokeOTP sends an email OTP before revoking a specific session.
// @Summary Start session revoke (OTP)
// @Tags sessions
// @Security BearerAuth
// @Produce json
// @Success 200 {object} SessionRevokeOTPResponse
// @Failure 400 {object} ErrEnvelope
// @Router /v1/sessions/revoke-otp [post]
func (s *Server) handleSessionRevokeOTP(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	if err := s.auth.StartSessionRevokeOTP(r.Context(), uid); err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "otp_sent"})
}

type revokeBody struct {
	Code string `json:"code"`
}

// handleSessionRevoke revokes one refresh session after OTP verification.
// @Summary Revoke session
// @Tags sessions
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param sessionID path string true "Session UUID"
// @Param body body SessionRevokeRequestBody true "OTP from email"
// @Success 204 "No content"
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope "Invalid OTP"
// @Router /v1/sessions/{sessionID}/revoke [post]
func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	sid, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad session id")
		return
	}
	var b revokeBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.auth.RevokeSessionWithOTP(r.Context(), uid, sid, b.Code); err != nil {
		if errors.Is(err, service.ErrOTPInvalid) {
			s.writeErr(w, http.StatusUnauthorized, "invalid otp")
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSessionDelete revokes one of the caller's own sessions directly (no OTP).
// @Summary Revoke own session
// @Description Immediately revokes one of your refresh sessions; you're already authenticated, so no email OTP is needed.
// @Tags sessions
// @Security BearerAuth
// @Param sessionID path string true "Session UUID"
// @Success 204 "No content"
// @Failure 400 {object} ErrEnvelope
// @Failure 404 {object} ErrEnvelope
// @Router /v1/sessions/{sessionID} [delete]
func (s *Server) handleSessionDelete(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	sid, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad session id")
		return
	}
	if err := s.auth.RevokeOwnSession(r.Context(), uid, sid); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			s.writeErr(w, http.StatusNotFound, "session not found")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListRoles returns all roles.
// @Summary List roles
// @Tags roles
// @Security BearerAuth
// @Produce json
// @Param q query string false "Case-insensitive role-name substring"
// @Param cursor query string false "Opaque keyset cursor; omit on first request"
// @Param page_size query int false "Items per page (max 100)"
// @Success 200 {object} RolesListResponse
// @Failure 500 {object} ErrEnvelope
// @Router /v1/roles [get]
func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	pageSize := pageSize(r)
	cursor, err := decodeCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid cursor")
		return
	}
	list, next, total, err := s.auth.RolesPage(r.Context(), r.URL.Query().Get("q"), cursor, pageSize)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"roles": list, "page_size": pageSize, "total": total, "next_cursor": encodeCursor(next)})
}

type createRoleBody struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	ParentID    string   `json:"parent_id"`
	ParentIDs   []string `json:"parent_ids"`
}

func normalizeRoleName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return "", errors.New("role name must contain 1 to 100 characters")
	}
	return name, nil
}

// handleCreateRole creates a role (superuser only), optionally under a parent.
// @Summary Create role
// @Tags roles
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body CreateRoleRequestBody true "Role name, description and optional parent_id"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Success 201 {object} CreateRoleResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Router /v1/roles [post]
func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	var b createRoleBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	name, err := normalizeRoleName(b.Name)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	parentIDs := make([]uuid.UUID, 0, len(b.ParentIDs)+1)
	if p := strings.TrimSpace(b.ParentID); p != "" {
		pid, err := uuid.Parse(p)
		if err != nil {
			s.writeErr(w, http.StatusBadRequest, "bad parent_id")
			return
		}
		parentIDs = append(parentIDs, pid)
	}
	for _, rawParentID := range b.ParentIDs {
		pid, parseErr := uuid.Parse(strings.TrimSpace(rawParentID))
		if parseErr != nil {
			s.writeErr(w, http.StatusBadRequest, "bad parent_ids")
			return
		}
		parentIDs = append(parentIDs, pid)
	}
	id, err := s.auth.CreateRole(r.Context(), uid, name, b.Description, parentIDs)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "superuser only")
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]string{"role_id": id.String()})
}

// handleDeleteRole deletes a role (superuser only). Children are re-parented.
// @Summary Delete role
// @Tags roles
// @Security BearerAuth
// @Param roleID path string true "Role UUID"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Success 204 "No content"
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/roles/{roleID} [delete]
func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad role id")
		return
	}
	if err := s.auth.DeleteRole(r.Context(), uid, rid); err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "superuser only")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type setParentBody struct {
	ParentID string `json:"parent_id"`
}

// handleSetRoleParent sets or clears a role's parent (superuser only).
// @Summary Set role parent
// @Description Establishes the role hierarchy. Pass an empty parent_id to detach. Rejects cycles.
// @Tags roles
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param roleID path string true "Role UUID"
// @Param body body SetRoleParentRequest true "Parent role UUID or empty to clear"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Success 204 "No content"
// @Failure 400 {object} ErrEnvelope "Bad id or cycle"
// @Failure 403 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/roles/{roleID}/parent [patch]
func (s *Server) handleSetRoleParent(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad role id")
		return
	}
	var b setParentBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	var parent *uuid.UUID
	if p := strings.TrimSpace(b.ParentID); p != "" {
		pid, err := uuid.Parse(p)
		if err != nil {
			s.writeErr(w, http.StatusBadRequest, "bad parent_id")
			return
		}
		parent = &pid
	}
	if err := s.auth.SetRoleParent(r.Context(), uid, rid, parent); err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "superuser only")
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleMountRole mounts a role under one additional parent.
// @Summary Mount role under parent
// @Description Adds a parent edge without replacing existing mounts. Membership and role-admin authority inherit through every parent path. Cycles are rejected.
// @Tags roles
// @Security BearerAuth
// @Accept json
// @Param roleID path string true "Role UUID"
// @Param body body MountRoleRequest true "Parent role UUID"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Success 204 "No content"
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Router /v1/roles/{roleID}/mounts [post]
func (s *Server) handleMountRole(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad role id")
		return
	}
	var b setParentBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	pid, err := uuid.Parse(strings.TrimSpace(b.ParentID))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad parent_id")
		return
	}
	if err := s.auth.Mount(r.Context(), uid, rid, pid); err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "manager of both roles required")
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleUnmountRole removes one parent edge while preserving all other mounts.
// @Summary Unmount role from parent
// @Tags roles
// @Security BearerAuth
// @Param roleID path string true "Role UUID"
// @Param parentID path string true "Parent role UUID"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Success 204 "No content"
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Router /v1/roles/{roleID}/mounts/{parentID} [delete]
func (s *Server) handleUnmountRole(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad role id")
		return
	}
	pid, err := uuid.Parse(chi.URLParam(r, "parentID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad parent id")
		return
	}
	if err := s.auth.Unmount(r.Context(), uid, rid, pid); err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "manager of both roles required")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListSubgroups lists direct or recursive descendants.
// @Summary List role subgroups
// @Tags roles
// @Security BearerAuth
// @Param roleID path string true "Role UUID"
// @Param recursive query bool false "Include all descendants"
// @Success 200 {object} RolesListResponse
// @Router /v1/roles/{roleID}/subgroups [get]
func (s *Server) handleListSubgroups(w http.ResponseWriter, r *http.Request) {
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad role id")
		return
	}
	recursive := r.URL.Query().Get("recursive") == "true"
	roles, err := s.auth.Subgroups(r.Context(), rid, recursive)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func normalizeTags(tags []string) ([]string, error) {
	if len(tags) > 32 {
		return nil, errors.New("at most 32 tags are allowed")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(tags))
	for _, raw := range tags {
		tag := strings.ToLower(strings.TrimSpace(raw))
		if tag == "" || len(tag) > 64 {
			return nil, errors.New("tags must contain 1 to 64 characters")
		}
		if !seen[tag] {
			seen[tag] = true
			out = append(out, tag)
		}
	}
	return out, nil
}

func normalizeRoleTagRename(oldTag, newTag string) (string, string, error) {
	oldTags, err := normalizeTags([]string{oldTag})
	if err != nil {
		return "", "", err
	}
	newTags, err := normalizeTags([]string{newTag})
	if err != nil {
		return "", "", err
	}
	return oldTags[0], newTags[0], nil
}

// @Summary Add one role tag definition
// @Tags roles
// @Security BearerAuth
// @Param roleID path string true "Role UUID"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Param body body RoleTagPairRequest true "Tag pair"
// @Success 204
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Router /v1/roles/{roleID}/tags [post]
func (s *Server) handleAddRoleTag(w http.ResponseWriter, r *http.Request) {
	s.handleRoleTagPair(w, r, true)
}

// @Summary Delete one role tag definition
// @Description Membership grants are preserved so re-adding the definition restores authorization.
// @Tags roles
// @Security BearerAuth
// @Param roleID path string true "Role UUID"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Param body body RoleTagPairRequest true "Tag pair"
// @Success 204
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Router /v1/roles/{roleID}/tags [delete]
func (s *Server) handleDeleteRoleTag(w http.ResponseWriter, r *http.Request) {
	s.handleRoleTagPair(w, r, false)
}

// @Summary Rename one role tag and migrate its membership grants
// @Tags roles
// @Security BearerAuth
// @Param roleID path string true "Role UUID"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Param body body RenameRoleTagRequest true "Old and new tag names"
// @Success 204
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Router /v1/roles/{roleID}/tags [patch]
func (s *Server) handleRenameRoleTag(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserID(r.Context())
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad role id")
		return
	}
	var body struct {
		OldTag string `json:"old_tag"`
		NewTag string `json:"new_tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	oldTag, newTag, err := normalizeRoleTagRename(body.OldTag, body.NewTag)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.auth.RenameRoleTag(r.Context(), actor, rid, oldTag, newTag); err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "role manager required")
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRoleTagPair(w http.ResponseWriter, r *http.Request, add bool) {
	actor, _ := UserID(r.Context())
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad role id")
		return
	}
	var body struct {
		Tag string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	tags, err := normalizeTags([]string{body.Tag})
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err = s.auth.ChangeRoleTag(r.Context(), actor, rid, tags[0], add)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "role manager required")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListRoleMembers lists active members of a role (superuser or role admin).
// @Summary List role members
// @Description Returns all users holding the role, admins first, with login and email.
// @Tags roles
// @Security BearerAuth
// @Produce json
// @Param roleID path string true "Role UUID"
// @Success 200 {object} RoleMembersResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/roles/{roleID}/members [get]
func (s *Server) handleListRoleMembers(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad role id")
		return
	}
	members, err := s.auth.RoleMembers(r.Context(), uid, rid)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(members))
	for _, m := range members {
		var email any
		if m.Email != nil {
			email = *m.Email
		}
		out = append(out, map[string]any{
			"user_id": m.UserID.String(), "login": m.Login, "email": email, "level": string(m.Level), "tags": m.Tags,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"members": out})
}

type patchRoleBody struct {
	Description string `json:"description"`
}

// handlePatchRole updates role description (superuser or role_admin for that role).
// @Summary Patch role description
// @Tags roles
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param roleID path string true "Role UUID"
// @Param body body PatchRoleRequestBody true "New description"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Success 204 "No content"
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/roles/{roleID}/description [patch]
func (s *Server) handlePatchRole(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad role id")
		return
	}
	var b patchRoleBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.auth.UpdateRoleDescription(r.Context(), uid, rid, b.Description); err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleUserRoles lists roles for a user (self or superuser).
// @Summary List user roles
// @Tags roles
// @Security BearerAuth
// @Produce json
// @Param userID path string true "User UUID"
// @Success 200 {object} UserRolesListResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/users/{userID}/roles [get]
func (s *Server) handleUserRoles(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserID(r.Context())
	target, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad user id")
		return
	}
	urs, err := s.auth.UserRoles(r.Context(), actor, target)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"user_roles": urs})
}

type assignBody struct {
	UserID     string     `json:"user_id"`
	Level      string     `json:"level"`
	ValidUntil *time.Time `json:"valid_until"`
	TagGrants  []string   `json:"tag_grants"`
}

// handleAssignRole assigns a role membership (authorized assigners only).
// @Summary Assign role to user
// @Tags roles
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param roleID path string true "Role UUID"
// @Param body body AssignRoleRequestBody true "Target user and level (member or role_admin)"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Success 204 "No content"
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Router /v1/roles/{roleID}/members [post]
func (s *Server) handleAssignRole(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserID(r.Context())
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad role id")
		return
	}
	var b assignBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	target, err := uuid.Parse(b.UserID)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad user_id")
		return
	}
	lvl := domain.RoleLevel(b.Level)
	if lvl != domain.RoleDirectMember && lvl != domain.RoleMember && lvl != domain.RoleRoleAdmin {
		s.writeErr(w, http.StatusBadRequest, "invalid level")
		return
	}
	tags, err := normalizeTags(b.TagGrants)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.auth.AssignRole(r.Context(), actor, target, rid, lvl, b.ValidUntil, tags); err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// @Summary Grant one tag to a role membership
// @Tags roles
// @Security BearerAuth
// @Param roleID path string true "Role UUID"
// @Param userID path string true "User UUID"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Param body body RoleTagPairRequest true "Tag"
// @Success 204
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Router /v1/roles/{roleID}/members/{userID}/tags [post]
func (s *Server) handleAddUserRoleTag(w http.ResponseWriter, r *http.Request) {
	s.handleUserRoleTagPair(w, r, true)
}

// @Summary Revoke one tag from a role membership
// @Tags roles
// @Security BearerAuth
// @Param roleID path string true "Role UUID"
// @Param userID path string true "User UUID"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Param body body RoleTagPairRequest true "Tag"
// @Success 204
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Router /v1/roles/{roleID}/members/{userID}/tags [delete]
func (s *Server) handleDeleteUserRoleTag(w http.ResponseWriter, r *http.Request) {
	s.handleUserRoleTagPair(w, r, false)
}

func (s *Server) handleUserRoleTagPair(w http.ResponseWriter, r *http.Request, add bool) {
	actor, _ := UserID(r.Context())
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad role id")
		return
	}
	target, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad user id")
		return
	}
	var body struct {
		Tag string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	tags, err := normalizeTags([]string{body.Tag})
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err = s.auth.ChangeMembershipTag(r.Context(), actor, target, rid, tags[0], add)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "role manager required")
			return
		}
		if errors.Is(err, service.ErrNotFound) {
			s.writeErr(w, http.StatusBadRequest, "role not found")
			return
		}
		if errors.Is(err, service.ErrTagNotConfigured) {
			s.writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRemoveRole removes a user's membership in a role.
// @Summary Remove role membership
// @Tags roles
// @Security BearerAuth
// @Param roleID path string true "Role UUID"
// @Param userID path string true "User UUID"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Success 204 "No content"
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/roles/{roleID}/members/{userID} [delete]
func (s *Server) handleRemoveRole(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserID(r.Context())
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad role id")
		return
	}
	target, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad user id")
		return
	}
	if err := s.auth.RemoveRole(r.Context(), actor, target, rid); err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type reqRoleBody struct {
	TargetUserID string `json:"target_user_id"`
}

// handleRoleRequest creates a request to join a role (self or on behalf of target_user_id if allowed).
// @Summary Request role membership
// @Tags roles
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param roleID path string true "Role UUID"
// @Param body body RoleRequestCreateBody false "Optional target user (defaults to caller)"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Success 201 {object} RoleRequestCreateResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Router /v1/roles/{roleID}/requests [post]
func (s *Server) handleRoleRequest(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserID(r.Context())
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad role id")
		return
	}
	var b reqRoleBody
	_ = json.NewDecoder(r.Body).Decode(&b)
	target := actor
	if b.TargetUserID != "" {
		tid, err := uuid.Parse(b.TargetUserID)
		if err != nil {
			s.writeErr(w, http.StatusBadRequest, "bad target_user_id")
			return
		}
		target = tid
	}
	// A role manager (superuser or admin of this role / an ancestor) doesn't need
	// approval — the membership is granted immediately. Everyone else creates a
	// pending request for a manager to decide.
	granted, id, err := s.auth.RequestRole(r.Context(), actor, target, rid)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "only a role manager may request membership for another user")
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if granted {
		s.writeJSON(w, http.StatusCreated, map[string]any{"status": "granted"})
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"status": "pending", "request_id": id.String()})
}

// handleListRoleRequests lists pending role requests (superuser or role_admin).
// @Summary List pending role requests
// @Tags roles
// @Security BearerAuth
// @Produce json
// @Param roleID path string true "Role UUID"
// @Success 200 {object} RoleRequestsListResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/roles/{roleID}/requests [get]
func (s *Server) handleListRoleRequests(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad role id")
		return
	}
	list, err := s.auth.PendingRoleRequests(r.Context(), uid, rid)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"requests": list})
}

type decideBody struct {
	Approve bool `json:"approve"`
}

// handleDecideRoleRequest approves or rejects a role request.
// @Summary Decide role request
// @Tags roles
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param requestID path string true "Request UUID"
// @Param body body DecideRoleRequestBody true "Approve or reject"
// @Param X-CSRF-Token header string false "Required for human access tokens; omitted for verified service tokens"
// @Success 204 "No content"
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Failure 404 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/role-requests/{requestID}/decide [post]
func (s *Server) handleDecideRoleRequest(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserID(r.Context())
	reqID, err := uuid.Parse(chi.URLParam(r, "requestID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad request id")
		return
	}
	var b decideBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.auth.DecideRoleRequest(r.Context(), actor, reqID, b.Approve); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			s.writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
