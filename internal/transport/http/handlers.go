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
		out["expires_at"] = prev.ExpiresAt.UTC().Format(time.RFC3339)
	}
	s.writeJSON(w, http.StatusOK, out)
}

type createInviteBody struct {
	Email      string `json:"email"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// handleCreateRegistrationInvite creates a new registration invite (superuser only).
// @Summary Create registration invite
// @Tags admin
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param X-CSRF-Token header string true "Must match csrf_token cookie (set after login)"
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
	ttl := time.Duration(b.TTLSeconds) * time.Second
	var locked *string
	if e := strings.TrimSpace(b.Email); e != "" {
		locked = &e
	}
	raw, exp, regURL, err := s.auth.CreateRegistrationInvite(r.Context(), uid, locked, ttl)
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
	s.writeJSON(w, http.StatusOK, map[string]any{"otp_sent": res.OTPRequired})
}

type verifyBody struct {
	Login       string `json:"login"`
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
	tokens, _, err := s.auth.LoginVerifyOTP(r.Context(), b.Login, b.Code, b.DeviceID, b.DeviceLabel)
	if err != nil {
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
		"access_token": tokens.AccessToken,
		"expires_at":   tokens.ExpiresAt.UTC().Format(time.RFC3339),
		"csrf_token":   csrf.String(),
	})
}

// handleRefresh rotates the refresh token (requires refresh cookie + CSRF header).
// @Summary Refresh access token
// @Description Requires HttpOnly refresh cookie (name from REFRESH_COOKIE_NAME, default refresh_token) and X-CSRF-Token matching the csrf_token cookie.
// @Tags auth
// @Accept json
// @Produce json
// @Param X-CSRF-Token header string true "Must match csrf_token cookie"
// @Param body body RefreshRequestBody false "Optional device metadata"
// @Success 200 {object} TokenPairResponse
// @Failure 401 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope "CSRF validation failed"
// @Router /v1/auth/refresh [post]
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(s.cfg.RefreshCookieName)
	if err != nil || c == nil || c.Value == "" {
		s.writeErr(w, http.StatusUnauthorized, "missing refresh cookie")
		return
	}
	var body struct {
		DeviceID    string `json:"device_id"`
		DeviceLabel string `json:"device_label"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	tokens, err := s.auth.Refresh(r.Context(), c.Value, body.DeviceID, body.DeviceLabel)
	if err != nil {
		s.writeErr(w, http.StatusUnauthorized, "refresh failed")
		return
	}
	maxAge := int(s.cfg.RefreshTokenTTL.Seconds())
	s.setRefreshCookie(w, tokens.RefreshToken, maxAge)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tokens.AccessToken,
		"expires_at":   tokens.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// handleLogout revokes the current refresh session and clears cookies.
// @Summary Logout
// @Description Requires X-CSRF-Token; sends refresh cookie if present (REFRESH_COOKIE_NAME, default refresh_token).
// @Tags auth
// @Param X-CSRF-Token header string true "Must match csrf_token cookie"
// @Success 204 "No content"
// @Failure 403 {object} ErrEnvelope "CSRF validation failed"
// @Router /v1/auth/logout [post]
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(s.cfg.RefreshCookieName)
	if err == nil && c != nil {
		_ = s.auth.Logout(r.Context(), c.Value)
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
	u, err := s.repo.GetUserByID(r.Context(), uid)
	if err != nil || u == nil {
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
}

// handleChangePassword changes password for the authenticated user.
// @Summary Change password
// @Tags auth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body ChangePasswordRequestBody true "Old and new password"
// @Success 204 "No content"
// @Failure 400 {object} ErrEnvelope "Password policy or validation"
// @Failure 401 {object} ErrEnvelope "Invalid old password"
// @Failure 404 {object} ErrEnvelope
// @Router /v1/auth/password [post]
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	var b pwdBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	err := s.auth.ChangePassword(r.Context(), uid, b.OldPassword, b.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			s.writeErr(w, http.StatusUnauthorized, "invalid old password")
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
	list, err := s.repo.ListRefreshSessions(r.Context(), uid)
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

// handleListRoles returns all roles.
// @Summary List roles
// @Tags roles
// @Security BearerAuth
// @Produce json
// @Success 200 {object} RolesListResponse
// @Failure 500 {object} ErrEnvelope
// @Router /v1/roles [get]
func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	list, err := s.repo.ListRoles(r.Context())
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"roles": list})
}

type createRoleBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// handleCreateRole creates a role (superuser only).
// @Summary Create role
// @Tags roles
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body CreateRoleRequestBody true "Role name and description"
// @Success 201 {object} CreateRoleResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Router /v1/roles [post]
func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	ok, err := s.auth.IsSuperuser(r.Context(), uid)
	if err != nil || !ok {
		s.writeErr(w, http.StatusForbidden, "superuser only")
		return
	}
	var b createRoleBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	id, err := s.repo.CreateRole(r.Context(), b.Name, b.Description)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]string{"role_id": id.String()})
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
	su, _ := s.auth.IsSuperuser(r.Context(), uid)
	ra, _ := s.auth.IsRoleAdmin(r.Context(), uid, rid)
	if !su && !ra {
		s.writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var b patchRoleBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.repo.UpdateRoleDescription(r.Context(), rid, b.Description); err != nil {
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
	if actor != target {
		su, err := s.auth.IsSuperuser(r.Context(), actor)
		if err != nil {
			s.writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !su {
			s.writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
	}
	urs, err := s.repo.ListUserRoles(r.Context(), target, time.Now())
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"user_roles": urs})
}

type assignBody struct {
	UserID     string     `json:"user_id"`
	Level      string     `json:"level"`
	ValidUntil *time.Time `json:"valid_until"`
}

// handleAssignRole assigns a role membership (authorized assigners only).
// @Summary Assign role to user
// @Tags roles
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param roleID path string true "Role UUID"
// @Param body body AssignRoleRequestBody true "Target user and level (member or role_admin)"
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
	ok, err := s.auth.CanAssignRole(r.Context(), actor, rid)
	if err != nil || !ok {
		s.writeErr(w, http.StatusForbidden, "forbidden")
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
	if lvl != domain.RoleMember && lvl != domain.RoleRoleAdmin {
		s.writeErr(w, http.StatusBadRequest, "invalid level")
		return
	}
	gb := actor
	if err := s.repo.AssignUserRole(r.Context(), target, rid, lvl, &gb, time.Now(), b.ValidUntil); err != nil {
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
	ok, err := s.auth.CanAssignRole(r.Context(), actor, rid)
	if err != nil || !ok {
		s.writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.repo.RemoveUserRole(r.Context(), target, rid); err != nil {
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
// @Success 201 {object} RoleRequestCreateResponse
// @Failure 400 {object} ErrEnvelope
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
	id, err := s.repo.CreateRoleRequest(r.Context(), actor, target, rid)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]string{"request_id": id.String()})
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
	su, _ := s.auth.IsSuperuser(r.Context(), uid)
	ra, _ := s.auth.IsRoleAdmin(r.Context(), uid, rid)
	if !su && !ra {
		s.writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	list, err := s.repo.ListPendingRoleRequests(r.Context(), rid)
	if err != nil {
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
	req, err := s.repo.GetRoleRequest(r.Context(), reqID)
	if err != nil || req == nil {
		s.writeErr(w, http.StatusNotFound, "not found")
		return
	}
	ok, err := s.auth.CanAssignRole(r.Context(), actor, req.RoleID)
	if err != nil || !ok {
		s.writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var b decideBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.repo.DecideRoleRequest(r.Context(), reqID, b.Approve, actor); err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if b.Approve {
		gb := actor
		if err := s.repo.AssignUserRole(r.Context(), req.TargetUserID, req.RoleID, domain.RoleMember, &gb, time.Now(), nil); err != nil {
			s.writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
