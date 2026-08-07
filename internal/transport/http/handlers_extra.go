package httptransport

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/jwtutil"
	"github.com/olegkapshai/auth-master/internal/repository"
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
// @Param q query string false "Case-insensitive login or email substring"
// @Param cursor query string false "Opaque keyset cursor; omit on first request"
// @Param page_size query int false "Items per page (max 100)"
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
	pageSize := pageSize(r)
	cursor, err := decodeCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid cursor")
		return
	}
	list, next, total, err := s.repo.SearchUsers(r.Context(), r.URL.Query().Get("q"), cursor, pageSize, cursor == nil)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, u := range list {
		out = append(out, map[string]any{
			"id": u.ID.String(), "login": u.Login, "email": u.Email, "kind": u.Kind,
			"superuser": u.Superuser, "banned_at": u.BannedAt, "ban_reason": u.BanReason, "created_at": u.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"users": out, "page_size": pageSize, "total": total, "next_cursor": encodeCursor(next)})
}

func pageSize(r *http.Request) int {
	size := 25
	if n, err := strconv.Atoi(r.URL.Query().Get("page_size")); err == nil && n > 0 && n <= 100 {
		size = n
	}
	return size
}

func encodeCursor(cursor *repository.PageCursor) string {
	if cursor == nil {
		return ""
	}
	raw, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeCursor(raw string) (*repository.PageCursor, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var cursor repository.PageCursor
	if err := json.Unmarshal(data, &cursor); err != nil || cursor.Sort == "" || cursor.ID == uuid.Nil {
		return nil, errors.New("invalid cursor")
	}
	return &cursor, nil
}

type banUserBody struct {
	Reason string `json:"reason"`
}

// handleBanUser bans a user and revokes refresh sessions.
// @Summary Ban user
// @Tags admin
// @Security BearerAuth
// @Param userID path string true "User UUID"
// @Param X-CSRF-Token header string true "CSRF token matching the csrf_token cookie"
// @Param body body BanUserRequest true "Reason"
// @Success 204
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Failure 404 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/admin/users/{userID}/ban [post]
func (s *Server) handleBanUser(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserID(r.Context())
	target, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad user id")
		return
	}
	var body banUserBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.auth.BanUser(r.Context(), actor, target, body.Reason); err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "superuser only")
			return
		}
		if errors.Is(err, service.ErrCannotBanSelf) || errors.Is(err, service.ErrCannotBanSuperuser) {
			s.writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, service.ErrNotFound) {
			s.writeErr(w, http.StatusNotFound, "user not found")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type tokenRoleCheckBody struct {
	Token    string `json:"token"`
	RoleName string `json:"role_name"`
	Tag      string `json:"tag"`
}

func normalizeTokenRoleCheck(body tokenRoleCheckBody, requireTag bool) (token, roleName, tag string, err error) {
	token = strings.TrimSpace(body.Token)
	roleName = strings.TrimSpace(body.RoleName)
	tag = strings.TrimSpace(body.Tag)
	if token == "" || roleName == "" || (requireTag && tag == "") {
		return "", "", "", errors.New("token and role_name are required" + map[bool]string{true: "; tag is also required"}[requireTag])
	}
	return token, roleName, tag, nil
}

func (s *Server) tokenSubject(w http.ResponseWriter, r *http.Request, token string) (uuid.UUID, bool) {
	claims, err := s.auth.VerifyAccessToken(r.Context(), token, jwtutil.TypeAccess)
	if err != nil {
		if errors.Is(err, service.ErrStaleSigningKey) {
			w.Header().Set("X-Token-Stale", "1")
		}
		s.writeErr(w, http.StatusUnauthorized, "invalid access token")
		return uuid.Nil, false
	}
	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		s.writeErr(w, http.StatusUnauthorized, "invalid access token subject")
		return uuid.Nil, false
	}
	return uid, true
}

// @Summary Check a role using an access token from JSON
// @Description Intended for another service authorizing a human caller. The user ID is derived only from the verified access token.
// @Tags auth
// @Accept json
// @Produce json
// @Param body body TokenHasRoleRequest true "Access token and role name"
// @Success 200 {object} HasRoleResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope
// @Router /v1/auth/has-role [post]
func (s *Server) handleTokenCheckRole(w http.ResponseWriter, r *http.Request) {
	s.handleTokenRoleCheck(w, r, false)
}

// @Summary Check a role tag using an access token from JSON
// @Description Intended for another service authorizing a human caller. Role and tag inheritance use the normal authorization rules.
// @Tags auth
// @Accept json
// @Produce json
// @Param body body TokenHasRoleWithTagRequest true "Access token, role name, and tag"
// @Success 200 {object} HasRoleWithTagResponse
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope
// @Router /v1/auth/has-role-with-tag [post]
func (s *Server) handleTokenCheckRoleWithTag(w http.ResponseWriter, r *http.Request) {
	s.handleTokenRoleCheck(w, r, true)
}

func (s *Server) handleTokenRoleCheck(w http.ResponseWriter, r *http.Request, withTag bool) {
	var body tokenRoleCheckBody
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	token, roleName, tag, err := normalizeTokenRoleCheck(body, withTag)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	uid, ok := s.tokenSubject(w, r, token)
	if !ok {
		return
	}
	if withTag {
		has, err := s.auth.UserHasRoleWithTag(r.Context(), uid, roleName, tag)
		if err != nil {
			s.writeErr(w, http.StatusUnauthorized, "authorization check failed")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]bool{"has_role_with_tag": has})
		return
	}
	has, err := s.auth.UserHasRoleName(r.Context(), uid, roleName)
	if err != nil {
		s.writeErr(w, http.StatusUnauthorized, "authorization check failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"has_role": has})
}

// @Summary Unban user
// @Tags admin
// @Security BearerAuth
// @Param userID path string true "User UUID"
// @Param X-CSRF-Token header string true "CSRF token matching the csrf_token cookie"
// @Success 204
// @Failure 400 {object} ErrEnvelope
// @Failure 401 {object} ErrEnvelope
// @Failure 403 {object} ErrEnvelope
// @Failure 404 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/admin/users/{userID}/ban [delete]
func (s *Server) handleUnbanUser(w http.ResponseWriter, r *http.Request) {
	actor, _ := UserID(r.Context())
	target, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "bad user id")
		return
	}
	if err := s.auth.UnbanUser(r.Context(), actor, target); err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.writeErr(w, http.StatusForbidden, "superuser only")
			return
		}
		if errors.Is(err, service.ErrNotFound) {
			s.writeErr(w, http.StatusNotFound, "user not found")
			return
		}
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRoleAccess returns the caller's effective membership and management
// rights after applying direct_member and DAG inheritance semantics.
// @Summary List effective role access for current user
// @Tags me
// @Security BearerAuth
// @Produce json
// @Success 200 {object} EffectiveRoleAccessResponse
// @Failure 401 {object} ErrEnvelope
// @Failure 500 {object} ErrEnvelope
// @Router /v1/me/role-access [get]
func (s *Server) handleRoleAccess(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	access, err := s.repo.ListEffectiveRoleAccess(r.Context(), uid, time.Now())
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(access))
	for _, item := range access {
		out = append(out, map[string]any{"role_id": item.RoleID.String(), "can_manage": item.CanManage})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"roles": out})
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

// @Summary Check named role and inherited tag
// @Tags me
// @Security BearerAuth
// @Param role_name query string true "Role name"
// @Param tag query string true "Capability tag"
// @Success 200 {object} HasRoleWithTagResponse
// @Router /v1/me/has-role-with-tag [get]
func (s *Server) handleCheckRoleWithTag(w http.ResponseWriter, r *http.Request) {
	uid, _ := UserID(r.Context())
	name := strings.TrimSpace(r.URL.Query().Get("role_name"))
	tag := strings.TrimSpace(r.URL.Query().Get("tag"))
	if name == "" || tag == "" {
		s.writeErr(w, http.StatusBadRequest, "role_name and tag required")
		return
	}
	has, err := s.auth.UserHasRoleWithTag(r.Context(), uid, name, tag)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"has_role_with_tag": has})
}
