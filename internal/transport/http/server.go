package httptransport

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/config"
	"github.com/olegkapshai/auth-master/internal/jwtutil"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/olegkapshai/auth-master/internal/service"
	httpSwagger "github.com/swaggo/http-swagger"

	_ "github.com/olegkapshai/auth-master/docs" // swagger docs
)

type Server struct {
	cfg    *config.Config
	auth   *service.Auth
	repo   repository.Repository
	log    *slog.Logger
	router chi.Router
}

func NewServer(cfg *config.Config, auth *service.Auth, repo repository.Repository, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, auth: auth, repo: repo, log: log}
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(InFlight)
	r.Use(RequestID)
	r.Use(SlogMiddleware(log))

	co := cors.Options{
		AllowedOrigins:   cfg.CORSAllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Request-ID"},
		AllowCredentials: true,
	}
	r.Use(cors.Handler(co))

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	r.Handle("/metrics", PrometheusHandler())
	r.Get("/swagger/*", httpSwagger.WrapHandler)

	r.Route("/v1", func(r chi.Router) {
		r.Get("/auth/registration-invite", s.handleRegistrationInvitePreview)
		r.Post("/auth/register", s.handleRegister)
		r.Post("/auth/login", s.handleLogin)
		r.Post("/auth/service-token", s.handleServiceToken)
		r.Get("/auth/token/info", s.handleTokenValidate)
		r.Get("/auth/token/verify-access", s.handleVerifyAccessTokenOnly)
		r.Post("/auth/login/verify-otp", s.handleLoginVerify)
		r.Post("/auth/login/magic-link", s.handleMagicLinkStart)
		r.Post("/auth/login/magic-link/verify", s.handleMagicLinkVerify)
		r.Post("/auth/password/reset/start", s.handlePasswordResetStart)
		r.Post("/auth/password/reset/complete", s.handlePasswordResetComplete)
		r.Post("/auth/refresh", s.handleRefresh)
		r.Post("/auth/logout", s.handleLogout)
		r.Post("/auth/step-up-2fa/complete", s.handleStepUp2FAComplete)

		r.Group(func(r chi.Router) {
			r.Use(s.requireAccessJWT)
			r.Get("/me", s.handleMe)
			r.Get("/me/has-role", s.handleCheckRole)
			r.Post("/auth/password/2fa", s.handleChangePassword2FAStart)
			r.Post("/auth/password", s.handleChangePassword)
			r.Post("/auth/step-up-2fa/start", s.handleStepUp2FAStart)
			r.Get("/auth/step-up-2fa/status", s.handleStepUp2FAStatus)
			r.With(s.csrf).Post("/auth/step-up-2fa/expire", s.handleStepUp2FAExpire)
			r.Get("/sessions", s.handleListSessions)
			r.Delete("/sessions/{sessionID}", s.handleSessionDelete)
			r.Post("/sessions/revoke-otp", s.handleSessionRevokeOTP)
			r.Post("/sessions/{sessionID}/revoke", s.handleSessionRevoke)

			r.With(s.csrf).Post("/admin/registration-invites", s.handleCreateRegistrationInvite)
			r.With(s.csrf).Post("/admin/signing-keys/rotate", s.handleRotateSigningKey)
			r.Get("/admin/users", s.handleListUsers)

			r.Get("/roles", s.handleListRoles)
			r.Post("/roles", s.handleCreateRole)
			r.Delete("/roles/{roleID}", s.handleDeleteRole)
			r.Patch("/roles/{roleID}/description", s.handlePatchRole)
			r.Patch("/roles/{roleID}/parent", s.handleSetRoleParent)
			r.Post("/roles/{roleID}/mounts", s.handleMountRole)
			r.Delete("/roles/{roleID}/mounts/{parentID}", s.handleUnmountRole)
			r.Get("/users/{userID}/roles", s.handleUserRoles)
			r.Get("/roles/{roleID}/members", s.handleListRoleMembers)
			r.Post("/roles/{roleID}/members", s.handleAssignRole)
			r.Delete("/roles/{roleID}/members/{userID}", s.handleRemoveRole)
			r.Post("/roles/{roleID}/requests", s.handleRoleRequest)
			r.Get("/roles/{roleID}/requests", s.handleListRoleRequests)
			r.Post("/role-requests/{requestID}/decide", s.handleDecideRoleRequest)
		})
	})

	s.router = r
	return s
}

func (s *Server) Handler() http.Handler { return s.router }

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeErr(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, map[string]string{"error": msg})
}

func clientIP(r *http.Request) net.IP {
	h := r.Header.Get("X-Forwarded-For")
	if h != "" {
		parts := strings.Split(h, ",")
		if len(parts) > 0 {
			return net.ParseIP(strings.TrimSpace(parts[0]))
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

// csrfOK implements the double-submit-cookie check (header must equal cookie).
func (s *Server) csrfOK(r *http.Request) bool {
	h := r.Header.Get(s.cfg.CSRFHeaderName)
	c, err := r.Cookie("csrf_token")
	return err == nil && c != nil && h != "" && c.Value == h
}

func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.csrfOK(r) {
			s.writeErr(w, http.StatusForbidden, "csrf validation failed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAccessJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		const p = "Bearer "
		if !strings.HasPrefix(h, p) {
			s.writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		tok := strings.TrimSpace(h[len(p):])
		claims, err := s.auth.VerifyAccessToken(r.Context(), tok, jwtutil.TypeAccess)
		if err != nil {
			if errors.Is(err, service.ErrStaleSigningKey) {
				w.Header().Set("X-Token-Stale", "1")
				s.writeErr(w, http.StatusUnauthorized, "token stale, refresh required")
				return
			}
			s.writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		uid, err := uuid.Parse(claims.Subject)
		if err != nil {
			s.writeErr(w, http.StatusUnauthorized, "invalid subject")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithUserID(r.Context(), uid)))
	})
}

func (s *Server) setRefreshCookie(w http.ResponseWriter, token string, maxAgeSec int) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.RefreshCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAgeSec,
		HttpOnly: true,
		Secure:   s.cfg.RefreshCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.RefreshCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.RefreshCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) setCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: false,
		Secure:   s.cfg.RefreshCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}
