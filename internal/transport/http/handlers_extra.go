package httptransport

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/olegkapshai/auth-master/internal/jwtutil"
	"github.com/olegkapshai/auth-master/internal/service"
)

type serviceTokenBody struct {
	Login  string `json:"login"`
	Secret string `json:"secret"`
}

// handleServiceToken issues a JWT for a service account (login + secret).
// @Summary Issue service access token
// @Tags auth
// @Accept json
// @Produce json
// @Param body body ServiceTokenRequestBody true "Service login and secret"
// @Success 200 {object} TokenPairResponse "access_token only (no csrf_token)"
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/auth/service-token [post]
func (s *Server) handleServiceToken(w http.ResponseWriter, r *http.Request) {
	var b serviceTokenBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	tok, exp, err := s.auth.IssueServiceToken(r.Context(), b.Login, b.Secret)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			s.writeErr(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"expires_at":   exp.UTC().Format(time.RFC3339),
	})
}

type stepUp2FAStartBody struct {
	TTLSeconds int64 `json:"ttl_seconds"`
}

// handleStepUp2FAStart begins an email OTP step-up challenge.
// @Summary Start step-up 2FA challenge
// @Tags auth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body StepUp2FAStartRequestBody false "Optional ttl_seconds (default 5m)"
// @Success 200 {object} StepUp2FAStartResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 404 {object} ErrEnvelope
// @Router /v1/auth/step-up-2fa/start [post]
func (s *Server) handleStepUp2FAStart(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	var b stepUp2FAStartBody
	_ = json.NewDecoder(r.Body).Decode(&b)
	ttl := time.Duration(b.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	corr, err := s.auth.BeginStepUp2FA(r.Context(), uid, ttl)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			s.writeErr(w, http.StatusNotFound, "user not found")
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"correlation_id": corr})
}

// handleStepUp2FAStatus returns status for a correlation id owned by the current user.
// @Summary Step-up 2FA status
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Param correlation_id query string true "Correlation id from start"
// @Success 200 {object} StepUp2FAStatusResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 404 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/auth/step-up-2fa/status [get]
func (s *Server) handleStepUp2FAStatus(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	corr := strings.TrimSpace(r.URL.Query().Get("correlation_id"))
	if corr == "" {
		s.writeErr(w, http.StatusBadRequest, "correlation_id required")
		return
	}
	st, err := s.auth.StepUp2FAStatusForUser(r.Context(), corr, uid)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			s.writeErr(w, http.StatusNotFound, "not found")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": st})
}

type stepUp2FAExpireBody struct {
	CorrelationID string `json:"correlation_id"`
}

// handleStepUp2FAExpire invalidates a step-up 2FA session (CSRF required).
// @Summary Expire step-up 2FA session
// @Tags auth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param X-CSRF-Token header string true "Must match csrf_token cookie"
// @Param body body StepUp2FAExpireRequestBody true "Correlation id"
// @Success 204 "No content"
// @Failure 400 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope "CSRF validation failed"
// @Failure 404 {object} ErrEnvelope
// @Router /v1/auth/step-up-2fa/expire [post]
func (s *Server) handleStepUp2FAExpire(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	var b stepUp2FAExpireBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.auth.ExpireStepUp2FASessionForUser(r.Context(), strings.TrimSpace(b.CorrelationID), uid); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			s.writeErr(w, http.StatusNotFound, "not found")
			return
		}
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleTokenValidate introspects an access or service JWT (Bearer).
// @Summary Introspect JWT (access or service)
// @Description Returns claims for valid access or service tokens. Response header X-Token-Stale: 1 when signing key rotated.
// @Tags auth
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} TokenIntrospectionResponse
// @Failure 400 {object} ErrEnvelope "Wrong token type"
// @Failure 401 {object} ErrEnvelope "Missing, invalid, or stale token"
// @Router /v1/auth/token/info [get]
func (s *Server) handleTokenValidate(w http.ResponseWriter, r *http.Request) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		s.writeErr(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	tok := strings.TrimSpace(h[len(p):])
	cl, err := s.auth.VerifyAccessOrServiceToken(r.Context(), tok)
	if err != nil {
		if errors.Is(err, service.ErrStaleSigningKey) {
			w.Header().Set("X-Token-Stale", "1")
			s.writeErr(w, http.StatusUnauthorized, "token stale")
			return
		}
		if errors.Is(err, service.ErrWrongTokenType) {
			s.writeErr(w, http.StatusBadRequest, "wrong token type")
			return
		}
		s.writeErr(w, http.StatusUnauthorized, "invalid token")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"subject": cl.Subject,
		"login":   cl.Login,
		"kid":     cl.Kid,
		"typ":     cl.Typ,
	})
}

// handleVerifyAccessTokenOnly validates that the Bearer token is a human access JWT (not service).
// @Summary Verify access JWT only
// @Tags auth
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Success 200 {object} TokenIntrospectionResponse
// @Failure 401 {object} ErrEnvelope
// @Router /v1/auth/token/verify-access [get]
func (s *Server) handleVerifyAccessTokenOnly(w http.ResponseWriter, r *http.Request) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		s.writeErr(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	tok := strings.TrimSpace(h[len(p):])
	cl, err := s.auth.VerifyAccessToken(r.Context(), tok, jwtutil.TypeAccess)
	if err != nil {
		if errors.Is(err, service.ErrStaleSigningKey) {
			w.Header().Set("X-Token-Stale", "1")
			s.writeErr(w, http.StatusUnauthorized, "token stale")
			return
		}
		s.writeErr(w, http.StatusUnauthorized, "invalid token")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"subject": cl.Subject,
		"login":   cl.Login,
		"kid":     cl.Kid,
		"typ":     cl.Typ,
	})
}

// handleRotateSigningKey rotates the JWT signing key (superuser, CSRF).
// @Summary Rotate signing key
// @Tags admin
// @Security BearerAuth
// @Param X-CSRF-Token header string true "Must match csrf_token cookie"
// @Success 204 "No content"
// @Failure 403 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/admin/signing-keys/rotate [post]
func (s *Server) handleRotateSigningKey(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	ok, err := s.auth.IsSuperuser(r.Context(), uid)
	if err != nil || !ok {
		s.writeErr(w, http.StatusForbidden, "superuser only")
		return
	}
	if err := s.auth.RotateSigningKey(r.Context()); err != nil {
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListUsers returns a page of users (superuser only).
// @Summary List users
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param limit query int false "Max users (default 100, max 500)"
// @Success 200 {object} AdminUsersResponse
// @Failure 403 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/admin/users [get]
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	ok, err := s.auth.IsSuperuser(r.Context(), uid)
	if err != nil || !ok {
		s.writeErr(w, http.StatusForbidden, "superuser only")
		return
	}
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	list, err := s.repo.ListUsers(r.Context(), limit)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, u := range list {
		out = append(out, map[string]any{
			"id": u.ID.String(), "login": u.Login, "email": u.Email, "kind": u.Kind,
			"superuser": u.Superuser, "created_at": u.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// handleCheckRole reports whether the current user has an active role by name.
// @Summary Check named role
// @Tags me
// @Security BearerAuth
// @Produce json
// @Param role_name query string true "Role name"
// @Success 200 {object} HasRoleResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/me/has-role [get]
func (s *Server) handleCheckRole(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	name := strings.TrimSpace(r.URL.Query().Get("role_name"))
	if name == "" {
		s.writeErr(w, http.StatusBadRequest, "role_name required")
		return
	}
	has, err := s.auth.UserHasRoleName(r.Context(), uid, name)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"has_role": has})
}
