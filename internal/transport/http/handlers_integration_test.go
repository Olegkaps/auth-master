package httptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/config"
	"github.com/olegkapshai/auth-master/internal/crypto"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/olegkapshai/auth-master/internal/migrate"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/olegkapshai/auth-master/internal/service"
	"github.com/olegkapshai/auth-master/internal/testutil"
	"github.com/stretchr/testify/require"
)

func httpIntegrationTestConfig() *config.Config {
	k := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	return &config.Config{
		DatabaseURL:                  "unused",
		PasswordHistoryEncryptionKey: k,
		SigningKeyMasterKey:          k,
		AccessTokenTTL:               time.Minute,
		RefreshTokenTTL:              time.Hour,
		SigningGracePeriod:           time.Minute,
		PasswordMaxAge:               time.Hour * 24 * 365,
		PasswordHistoryN:             5,
		OTPCodeTTL:                   time.Minute,
		OTPCodeLength:                6,
		MaxSessionsPerUser:           10,
		LoginFailWindow:              time.Minute,
		LoginFailMax:                 10,
		LoginLockDuration:            time.Minute,
		NotifyOnFailThreshold:        99,
		CORSAllowedOrigins:           []string{"http://localhost:5173"},
		CSRFHeaderName:               "X-CSRF-Token",
		RefreshCookieName:            "refresh_token",
		RegistrationInviteBaseURL:    "http://localhost:5173/register",
	}
}

func testRepoForHTTPIntegration(t *testing.T) (repository.Repository, func()) {
	t.Helper()
	ctx := context.Background()
	dsn, terminate := testutil.StartPostgres16TestcontainerForTest(t, ctx)
	db, err := migrate.Open(dsn)
	require.NoError(t, err)
	require.NoError(t, migrate.Up(db))
	cleanup := func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			_ = sqlDB.Close()
		}
		terminate()
	}
	return repository.New(db), cleanup
}

func mergeCookies(prev []*http.Cookie, upd []*http.Cookie) []*http.Cookie {
	byName := make(map[string]*http.Cookie)
	for _, c := range prev {
		byName[c.Name] = c
	}
	for _, c := range upd {
		byName[c.Name] = c
	}
	out := make([]*http.Cookie, 0, len(byName))
	for _, c := range byName {
		out = append(out, c)
	}
	return out
}

func seedRegistrationInvite(t *testing.T, a *service.Auth, repo repository.Repository, ctx context.Context) string {
	t.Helper()
	aid, err := repo.CreateHumanUser(ctx, "invite-admin-http", "invadminhttp@test.dev", "bootstrap-placeholder-hash")
	require.NoError(t, err)
	require.NoError(t, repo.SetSuperuser(ctx, aid, true))
	raw, _, _, err := a.CreateRegistrationInvite(ctx, aid, nil, time.Hour)
	require.NoError(t, err)
	return raw
}

func TestIntegration_HTTPMajorRoutes(t *testing.T) {
	repo, done := testRepoForHTTPIntegration(t)
	defer done()
	ctx := context.Background()
	cfg := httpIntegrationTestConfig()
	m := &mail.Sender{Host: "127.0.0.1", Port: 1025, From: "t@test.dev"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := service.NewAuth(cfg, repo, m, log)
	require.NoError(t, err)
	require.NoError(t, a.EnsureBootstrap(ctx))

	inv := seedRegistrationInvite(t, a, repo, ctx)

	srv := NewServer(cfg, a, repo, log)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	base := ts.URL

	t.Run("health_metrics_swagger", func(t *testing.T) {
		r, err := client.Get(base + "/healthz")
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)

		r, err = client.Get(base + "/metrics")
		require.NoError(t, err)
		b, _ := io.ReadAll(r.Body)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.Contains(t, string(b), "auth_http")

		r, err = client.Get(base + "/swagger/index.html")
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
	})

	t.Run("auth_validation_branches", func(t *testing.T) {
		r, err := client.Post(base+"/v1/auth/login", "application/json", strings.NewReader(`not-json`))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusBadRequest, r.StatusCode)

		r, err = client.Get(base + "/v1/auth/registration-invite?token=")
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
	})

	r, err := client.Get(base + "/v1/auth/registration-invite?token=" + inv)
	require.NoError(t, err)
	var prev map[string]any
	require.NoError(t, json.NewDecoder(r.Body).Decode(&prev))
	require.NoError(t, r.Body.Close())
	require.Equal(t, http.StatusOK, r.StatusCode)
	require.Equal(t, true, prev["valid"])

	// Register + promote to superuser (admin HTTP routes).
	regBody := fmt.Sprintf(`{"invite_token":%q,"login":"httpuser","email":"httpuser@test.dev","password":"password-one"}`, inv)
	r, err = client.Post(base+"/v1/auth/register", "application/json", strings.NewReader(regBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, r.StatusCode)
	var regOut struct {
		UserID string `json:"user_id"`
	}
	require.NoError(t, json.NewDecoder(r.Body).Decode(&regOut))
	require.NoError(t, r.Body.Close())
	uid, err := uuid.Parse(regOut.UserID)
	require.NoError(t, err)
	require.NoError(t, repo.SetSuperuser(ctx, uid, true))

	loginBody := `{"login":"httpuser","password":"password-one"}`
	req, err := http.NewRequest(http.MethodPost, base+"/v1/auth/login", strings.NewReader(loginBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	r, err = client.Do(req)
	require.NoError(t, err)
	require.NoError(t, r.Body.Close())
	require.Equal(t, http.StatusOK, r.StatusCode)

	_, err = repo.CreateEmailOTP(ctx, uid, domain.OTPLogin, a.IntegrationOTPHash("555555"), time.Now().Add(time.Minute), nil)
	require.NoError(t, err)

	verifyBody := `{"login":"httpuser","code":"555555","device_id":"dev-http","device_label":"test"}`
	r, err = client.Post(base+"/v1/auth/login/verify-otp", "application/json", strings.NewReader(verifyBody))
	require.NoError(t, err)
	sessionCookies := r.Cookies()
	var tokOut struct {
		AccessToken string `json:"access_token"`
		CSRFToken   string `json:"csrf_token"`
	}
	require.NoError(t, json.NewDecoder(r.Body).Decode(&tokOut))
	require.NoError(t, r.Body.Close())
	require.Equal(t, http.StatusOK, r.StatusCode)
	require.NotEmpty(t, tokOut.AccessToken)
	require.NotEmpty(t, tokOut.CSRFToken)
	require.NotEmpty(t, sessionCookies, "Set-Cookie from verify-otp (refresh + csrf); cookiejar alone is unreliable in some CI/container setups")

	authz := "Bearer " + tokOut.AccessToken
	csrf := strings.TrimSpace(tokOut.CSRFToken)

	do := func(method, path string, body io.Reader, extra http.Header) *http.Response {
		req, err := http.NewRequest(method, base+path, body)
		require.NoError(t, err)
		for _, c := range sessionCookies {
			req.AddCookie(c)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", authz)
		for k, v := range extra {
			for _, vv := range v {
				req.Header.Add(k, vv)
			}
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("me_token_introspection", func(t *testing.T) {
		r := do(http.MethodGet, "/v1/me", nil, nil)
		var me map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&me))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.Equal(t, "httpuser", me["login"])
		require.Equal(t, true, me["superuser"])

		req, err := http.NewRequest(http.MethodGet, base+"/v1/auth/token/info", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", authz)
		r2, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, r2.Body.Close())
		require.Equal(t, http.StatusOK, r2.StatusCode)

		r3, err := client.Get(base + "/v1/auth/token/verify-access")
		require.NoError(t, err)
		require.NoError(t, r3.Body.Close())
		require.Equal(t, http.StatusUnauthorized, r3.StatusCode)

		r4 := do(http.MethodGet, "/v1/auth/token/verify-access", nil, nil)
		require.NoError(t, r4.Body.Close())
		require.Equal(t, http.StatusOK, r4.StatusCode)
	})

	t.Run("refresh_logout_csrf", func(t *testing.T) {
		h := http.Header{}
		h.Set(cfg.CSRFHeaderName, csrf)
		r := do(http.MethodPost, "/v1/auth/refresh", bytes.NewReader([]byte(`{"device_id":"dev-http"}`)), h)
		var ref map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&ref))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.NotEmpty(t, ref["access_token"])
		sessionCookies = mergeCookies(sessionCookies, r.Cookies())

		r = do(http.MethodPost, "/v1/auth/logout", bytes.NewReader([]byte(`{}`)), h)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)
	})

	// New login session for RBAC / admin tests (logout cleared refresh).
	r, err = client.Post(base+"/v1/auth/login", "application/json", strings.NewReader(loginBody))
	require.NoError(t, err)
	require.NoError(t, r.Body.Close())
	require.Equal(t, http.StatusOK, r.StatusCode)
	_, err = repo.CreateEmailOTP(ctx, uid, domain.OTPLogin, a.IntegrationOTPHash("444444"), time.Now().Add(time.Minute), nil)
	require.NoError(t, err)
	r, err = client.Post(base+"/v1/auth/login/verify-otp", "application/json",
		strings.NewReader(`{"login":"httpuser","code":"444444","device_id":"dev2","device_label":"x"}`))
	require.NoError(t, err)
	sessionCookies = r.Cookies()
	require.NoError(t, json.NewDecoder(r.Body).Decode(&tokOut))
	require.NoError(t, r.Body.Close())
	require.Equal(t, http.StatusOK, r.StatusCode)
	authz = "Bearer " + tokOut.AccessToken
	csrf = strings.TrimSpace(tokOut.CSRFToken)

	do = func(method, path string, body io.Reader, extra http.Header) *http.Response {
		req, err := http.NewRequest(method, base+path, body)
		require.NoError(t, err)
		for _, c := range sessionCookies {
			req.AddCookie(c)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", authz)
		for k, v := range extra {
			for _, vv := range v {
				req.Header.Add(k, vv)
			}
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("roles_rbac_admin", func(t *testing.T) {
		r := do(http.MethodGet, "/v1/roles", nil, nil)
		var rolesOut map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&rolesOut))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)

		r = do(http.MethodPost, "/v1/roles", bytes.NewReader([]byte(`{"name":"http-role","description":"d"}`)), nil)
		var roleCreated map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&roleCreated))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusCreated, r.StatusCode)
		rid := roleCreated["role_id"]
		require.NotEmpty(t, rid)

		r = do(http.MethodPatch, "/v1/roles/"+rid+"/description", bytes.NewReader([]byte(`{"description":"d2"}`)), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)

		assignBody := fmt.Sprintf(`{"user_id":%q,"level":"member"}`, uid.String())
		r = do(http.MethodPost, "/v1/roles/"+rid+"/members", bytes.NewReader([]byte(assignBody)), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)

		r = do(http.MethodGet, "/v1/me/has-role?role_name=http-role", nil, nil)
		var has map[string]bool
		require.NoError(t, json.NewDecoder(r.Body).Decode(&has))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.True(t, has["has_role"])

		r = do(http.MethodGet, "/v1/users/"+uid.String()+"/roles", nil, nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)

		peerID, err := repo.CreateHumanUser(ctx, "peer-http", "peerhttp@test.dev", "x")
		require.NoError(t, err)
		reqBody := fmt.Sprintf(`{"target_user_id":%q}`, peerID.String())
		r = do(http.MethodPost, "/v1/roles/"+rid+"/requests", bytes.NewReader([]byte(reqBody)), nil)
		var reqOut map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&reqOut))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusCreated, r.StatusCode)
		reqID := reqOut["request_id"]

		r = do(http.MethodGet, "/v1/roles/"+rid+"/requests", nil, nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)

		r = do(http.MethodPost, "/v1/role-requests/"+reqID+"/decide", bytes.NewReader([]byte(`{"approve":true}`)), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)

		r = do(http.MethodDelete, "/v1/roles/"+rid+"/members/"+uid.String(), nil, nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)
	})

	t.Run("sessions_password_stepup_signing", func(t *testing.T) {
		r := do(http.MethodGet, "/v1/sessions", nil, nil)
		var sess struct {
			Sessions []struct {
				ID       string `json:"id"`
				DeviceID string `json:"device_id"`
			} `json:"sessions"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&sess))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.NotEmpty(t, sess.Sessions)
		var sid string
		for _, s := range sess.Sessions {
			if s.DeviceID == "dev2" {
				sid = s.ID
				break
			}
		}
		require.NotEmpty(t, sid)

		_, err := repo.CreateEmailOTP(ctx, uid, domain.OTPSessionRevoke, a.IntegrationOTPHash("888888"), time.Now().Add(time.Minute), nil)
		require.NoError(t, err)
		revBody := `{"code":"888888"}`
		req, err := http.NewRequest(http.MethodPost, base+"/v1/sessions/"+sid+"/revoke", strings.NewReader(revBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", authz)
		r2, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, r2.Body.Close())
		require.Equal(t, http.StatusNoContent, r2.StatusCode)

		r = do(http.MethodPost, "/v1/auth/password", bytes.NewReader([]byte(`{"old_password":"password-one","new_password":"password-two"}`)), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)

		r = do(http.MethodPost, "/v1/auth/step-up-2fa/start", bytes.NewReader([]byte(`{"ttl_seconds": 600}`)), nil)
		var st map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&st))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		corr := st["correlation_id"]
		require.NotEmpty(t, corr)

		r = do(http.MethodGet, "/v1/auth/step-up-2fa/status?correlation_id="+corr, nil, nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)

		h := http.Header{}
		h.Set(cfg.CSRFHeaderName, csrf)
		r = do(http.MethodPost, "/v1/auth/step-up-2fa/expire", bytes.NewReader([]byte(fmt.Sprintf(`{"correlation_id":%q}`, corr))), h)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)

		corr2 := "http-stepup-manual"
		require.NoError(t, repo.CreateStepUp2FASession(ctx, corr2, uid, time.Now().Add(10*time.Minute)))
		_, err = repo.CreateEmailOTP(ctx, uid, domain.OTPStepUp2FA, a.IntegrationOTPHash("777777"), time.Now().Add(time.Minute), &corr2)
		require.NoError(t, err)
		r, err = client.Post(base+"/v1/auth/step-up-2fa/complete", "application/json",
			strings.NewReader(fmt.Sprintf(`{"correlation_id":%q,"code":"777777"}`, corr2)))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
	})

	t.Run("admin_invites_users_service_token", func(t *testing.T) {
		h := http.Header{}
		h.Set(cfg.CSRFHeaderName, csrf)
		r := do(http.MethodPost, "/v1/admin/registration-invites", bytes.NewReader([]byte(`{"ttl_seconds":3600}`)), h)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusCreated, r.StatusCode)

		r = do(http.MethodGet, "/v1/admin/users?limit=50", nil, nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)

		sh, err := crypto.HashSecret("svc-plain")
		require.NoError(t, err)
		_, err = repo.CreateServiceUser(ctx, "svc-http", sh)
		require.NoError(t, err)
		r, err = client.Post(base+"/v1/auth/service-token", "application/json",
			strings.NewReader(`{"login":"svc-http","secret":"svc-plain"}`))
		require.NoError(t, err)
		var svcTok map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&svcTok))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		sat, _ := svcTok["access_token"].(string)
		require.NotEmpty(t, sat)

		req, err := http.NewRequest(http.MethodGet, base+"/v1/auth/token/info", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+sat)
		r2, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, r2.Body.Close())
		require.Equal(t, http.StatusOK, r2.StatusCode)

		r = do(http.MethodPost, "/v1/admin/signing-keys/rotate", bytes.NewReader([]byte(`{}`)), h)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)
	})
}
