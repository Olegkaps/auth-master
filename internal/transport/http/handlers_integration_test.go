package httptransport

import (
	"bytes"
	"context"
	"encoding/hex"
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
		SigningGracePeriod:           0,
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
	raw, _, _, err := a.CreateRegistrationInvite(ctx, aid, nil, false, time.Hour)
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
	regBody := fmt.Sprintf(`{"invite_token":%q,"login":"httpuser","email":"httpuser@test.dev","password":"Password-One1!"}`, inv)
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

	loginBody := `{"login":"httpuser","password":"Password-One1!"}`
	req, err := http.NewRequest(http.MethodPost, base+"/v1/auth/login", strings.NewReader(loginBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	r, err = client.Do(req)
	require.NoError(t, err)
	var loginOut struct {
		OTPSent        bool   `json:"otp_sent"`
		LoginChallenge string `json:"login_challenge"`
	}
	require.NoError(t, json.NewDecoder(r.Body).Decode(&loginOut))
	require.NoError(t, r.Body.Close())
	require.Equal(t, http.StatusOK, r.StatusCode)
	require.NotEmpty(t, loginOut.LoginChallenge)

	_, err = repo.CreateEmailOTP(ctx, uid, domain.OTPLogin, a.IntegrationOTPHash("555555"), time.Now().Add(time.Minute), &loginOut.LoginChallenge)
	require.NoError(t, err)

	verifyBody := fmt.Sprintf(`{"challenge":%q,"code":"555555","device_id":"dev-http","device_label":"test"}`, loginOut.LoginChallenge)
	r, err = client.Post(base+"/v1/auth/login/verify-otp", "application/json", strings.NewReader(verifyBody))
	require.NoError(t, err)
	sessionCookies := r.Cookies()
	var tokOut struct {
		AccessToken  string `json:"access_token"`
		CSRFToken    string `json:"csrf_token"`
		RefreshToken string `json:"refresh_token"`
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
		// No body credential and no refresh cookie is an authentication failure,
		// not a CSRF failure (there is no ambient credential to protect).
		cleanClient := &http.Client{Timeout: 30 * time.Second}
		r, err := cleanClient.Post(base+"/v1/auth/refresh", "application/json", strings.NewReader(`{}`))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusUnauthorized, r.StatusCode)

		// Cookie mode requires a matching double-submit header.
		r = do(http.MethodPost, "/v1/auth/refresh", bytes.NewReader([]byte(`{"device_id":"dev-http"}`)), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusForbidden, r.StatusCode)
		wrongCSRF := http.Header{}
		wrongCSRF.Set(cfg.CSRFHeaderName, "wrong")
		r = do(http.MethodPost, "/v1/auth/refresh", bytes.NewReader([]byte(`{"device_id":"dev-http"}`)), wrongCSRF)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusForbidden, r.StatusCode)

		h := http.Header{}
		h.Set(cfg.CSRFHeaderName, csrf)
		r = do(http.MethodPost, "/v1/auth/refresh", bytes.NewReader([]byte(`{"device_id":"dev-http"}`)), h)
		var ref map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&ref))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.NotEmpty(t, ref["access_token"])
		sessionCookies = mergeCookies(sessionCookies, r.Cookies())

		// Body-token mode needs neither cookies nor CSRF and takes precedence over
		// any ambient state. Use the token rotated by the cookie-mode request.
		bodyRefresh, _ := ref["refresh_token"].(string)
		require.NotEmpty(t, bodyRefresh)
		r, err = cleanClient.Post(base+"/v1/auth/refresh", "application/json",
			strings.NewReader(fmt.Sprintf(`{"device_id":"dev-http","refresh_token":%q}`, bodyRefresh)))
		require.NoError(t, err)
		var bodyRef map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&bodyRef))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		latestRefresh, _ := bodyRef["refresh_token"].(string)
		require.NotEmpty(t, latestRefresh)

		r = do(http.MethodPost, "/v1/auth/logout", bytes.NewReader([]byte(fmt.Sprintf(`{"refresh_token":%q}`, latestRefresh))), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)
	})

	// New login session for RBAC / admin tests (logout cleared refresh).
	r, err = client.Post(base+"/v1/auth/login", "application/json", strings.NewReader(loginBody))
	require.NoError(t, err)
	require.NoError(t, json.NewDecoder(r.Body).Decode(&loginOut))
	require.NoError(t, r.Body.Close())
	require.Equal(t, http.StatusOK, r.StatusCode)
	require.NotEmpty(t, loginOut.LoginChallenge)
	_, err = repo.CreateEmailOTP(ctx, uid, domain.OTPLogin, a.IntegrationOTPHash("444444"), time.Now().Add(time.Minute), &loginOut.LoginChallenge)
	require.NoError(t, err)
	r, err = client.Post(base+"/v1/auth/login/verify-otp", "application/json",
		strings.NewReader(fmt.Sprintf(`{"challenge":%q,"code":"444444","device_id":"dev2","device_label":"x"}`, loginOut.LoginChallenge)))
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

		// Hierarchy: create a child role, adjust parent, and reject a cycle.
		childBody := fmt.Sprintf(`{"name":"http-child","description":"c","parent_id":%q}`, rid)
		r = do(http.MethodPost, "/v1/roles", bytes.NewReader([]byte(childBody)), nil)
		var childCreated map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&childCreated))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusCreated, r.StatusCode)
		childID := childCreated["role_id"]
		require.NotEmpty(t, childID)

		r = do(http.MethodPatch, "/v1/roles/"+childID+"/parent", bytes.NewReader([]byte(`{"parent_id":""}`)), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)

		r = do(http.MethodPatch, "/v1/roles/"+childID+"/parent", bytes.NewReader([]byte(fmt.Sprintf(`{"parent_id":%q}`, rid))), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)

		// Add and remove a second mount without replacing the first one.
		r = do(http.MethodPost, "/v1/roles", bytes.NewReader([]byte(`{"name":"http-parent-two","description":"p2"}`)), nil)
		var parentTwo map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&parentTwo))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusCreated, r.StatusCode)
		parentTwoID := parentTwo["role_id"]
		r = do(http.MethodPost, "/v1/roles/"+childID+"/mounts", bytes.NewReader([]byte(fmt.Sprintf(`{"parent_id":%q}`, parentTwoID))), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)
		r = do(http.MethodDelete, "/v1/roles/"+childID+"/mounts/"+parentTwoID, nil, nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)
		// Mounting an ancestor below its descendant must be rejected as a cycle.
		r = do(http.MethodPost, "/v1/roles/"+rid+"/mounts", bytes.NewReader([]byte(fmt.Sprintf(`{"parent_id":%q}`, childID))), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusBadRequest, r.StatusCode)

		r = do(http.MethodGet, "/v1/roles/"+rid+"/subgroups?recursive=true", nil, nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		tagHeaders := http.Header{}
		tagHeaders.Set(cfg.CSRFHeaderName, csrf)
		for _, tag := range []string{"Read", "write"} {
			r = do(http.MethodPost, "/v1/roles/"+rid+"/tags", bytes.NewReader([]byte(fmt.Sprintf(`{"tag":%q}`, tag))), tagHeaders)
			require.NoError(t, r.Body.Close())
			require.Equal(t, http.StatusNoContent, r.StatusCode)
		}
		// Regression: bulk replacement is intentionally unsupported because it
		// can accidentally destroy existing definitions and grants.
		r = do(http.MethodPut, "/v1/roles/"+rid+"/tags", bytes.NewReader([]byte(`{"tags":["other"]}`)), tagHeaders)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusMethodNotAllowed, r.StatusCode)

		// rid under its own child would be a cycle → 400.
		r = do(http.MethodPatch, "/v1/roles/"+rid+"/parent", bytes.NewReader([]byte(fmt.Sprintf(`{"parent_id":%q}`, childID))), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusBadRequest, r.StatusCode)

		assignBody := fmt.Sprintf(`{"user_id":%q,"level":"member"}`, uid.String())
		r = do(http.MethodPost, "/v1/roles/"+rid+"/members", bytes.NewReader([]byte(assignBody)), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)

		// Effective access is server authoritative and includes inherited child access.
		r = do(http.MethodGet, "/v1/me/role-access", nil, nil)
		var accessOut struct {
			Roles []struct {
				RoleID    string `json:"role_id"`
				CanManage bool   `json:"can_manage"`
			} `json:"roles"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&accessOut))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.Contains(t, accessOut.Roles, struct {
			RoleID    string `json:"role_id"`
			CanManage bool   `json:"can_manage"`
		}{RoleID: childID, CanManage: false})

		// Initial membership grants commit atomically: one undefined tag rolls
		// back the membership instead of leaving a partial success.
		atomicTarget, err := repo.CreateHumanUser(ctx, "atomic-http", "atomic-http@test.dev", "hash")
		require.NoError(t, err)
		badAtomicBody := fmt.Sprintf(`{"user_id":%q,"level":"member","tag_grants":["read","missing"]}`, atomicTarget.String())
		r = do(http.MethodPost, "/v1/roles/"+rid+"/members", bytes.NewReader([]byte(badAtomicBody)), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusBadRequest, r.StatusCode)
		ridUUID, err := uuid.Parse(rid)
		require.NoError(t, err)
		_, found, err := repo.GetUserRoleLevel(ctx, atomicTarget, ridUUID, time.Now())
		require.NoError(t, err)
		require.False(t, found)
		goodAtomicBody := fmt.Sprintf(`{"user_id":%q,"level":"member","tag_grants":["read"]}`, atomicTarget.String())
		r = do(http.MethodPost, "/v1/roles/"+rid+"/members", bytes.NewReader([]byte(goodAtomicBody)), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)
		r = do(http.MethodDelete, "/v1/roles/"+rid+"/members/"+atomicTarget.String()+"/tags", bytes.NewReader([]byte(`{"tag":"read"}`)), tagHeaders)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)
		r = do(http.MethodPost, "/v1/roles/"+rid+"/members/"+uid.String()+"/tags", bytes.NewReader([]byte(`{"tag":"read"}`)), tagHeaders)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)

		// List members (admins first, enriched with login/email).
		r = do(http.MethodGet, "/v1/roles/"+rid+"/members", nil, nil)
		var mem struct {
			Members []map[string]any `json:"members"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&mem))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.NotEmpty(t, mem.Members)

		r = do(http.MethodGet, "/v1/me/has-role?role_name=http-role", nil, nil)
		var has map[string]bool
		require.NoError(t, json.NewDecoder(r.Body).Decode(&has))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.True(t, has["has_role"])
		r = do(http.MethodGet, "/v1/me/has-role-with-tag?role_name=http-child&tag=READ", nil, nil)
		var tagged map[string]bool
		require.NoError(t, json.NewDecoder(r.Body).Decode(&tagged))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.True(t, tagged["has_role_with_tag"])
		r = do(http.MethodPatch, "/v1/roles/"+rid+"/tags", bytes.NewReader([]byte(`{"old_tag":"read","new_tag":"view"}`)), tagHeaders)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)
		r = do(http.MethodGet, "/v1/me/has-role-with-tag?role_name=http-child&tag=read", nil, nil)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&tagged))
		require.NoError(t, r.Body.Close())
		require.False(t, tagged["has_role_with_tag"])
		r = do(http.MethodGet, "/v1/me/has-role-with-tag?role_name=http-child&tag=view", nil, nil)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&tagged))
		require.NoError(t, r.Body.Close())
		require.True(t, tagged["has_role_with_tag"])
		r = do(http.MethodDelete, "/v1/roles/"+rid+"/tags", bytes.NewReader([]byte(`{"tag":"view"}`)), tagHeaders)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)
		r = do(http.MethodPost, "/v1/roles/"+rid+"/tags", bytes.NewReader([]byte(`{"tag":"view"}`)), tagHeaders)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)

		r = do(http.MethodGet, "/v1/users/"+uid.String()+"/roles", nil, nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)

		peerID, err := repo.CreateHumanUser(ctx, "peer-http", "peerhttp@test.dev", "x")
		require.NoError(t, err)
		// httpuser is a superuser (manager) → the request is auto-granted, no approval.
		reqBody := fmt.Sprintf(`{"target_user_id":%q}`, peerID.String())
		r = do(http.MethodPost, "/v1/roles/"+rid+"/requests", bytes.NewReader([]byte(reqBody)), nil)
		var reqOut map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&reqOut))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusCreated, r.StatusCode)
		require.Equal(t, "granted", reqOut["status"])

		// Seed a pending request from a non-manager, then approve it as the superuser.
		pendingID, err := repo.CreateRoleRequest(ctx, peerID, peerID, ridUUID)
		require.NoError(t, err)

		r = do(http.MethodGet, "/v1/roles/"+rid+"/requests", nil, nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)

		r = do(http.MethodPost, "/v1/role-requests/"+pendingID.String()+"/decide", bytes.NewReader([]byte(`{"approve":true}`)), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)

		r = do(http.MethodDelete, "/v1/roles/"+rid+"/members/"+uid.String(), nil, nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)

		r = do(http.MethodDelete, "/v1/roles/"+childID, nil, nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)
	})

	// A service can verify a caller's token and then authorize by role — both over
	// the API: introspect the JWT, then check has-role.
	t.Run("verify_token_then_check_role", func(t *testing.T) {
		roleID, err := repo.CreateRole(ctx, "gate-role", "", nil)
		require.NoError(t, err)
		require.NoError(t, repo.AssignUserRole(ctx, uid, roleID, domain.RoleMember, &uid, time.Now(), nil))
		require.NoError(t, repo.AddRoleTag(ctx, roleID, "read"))
		require.NoError(t, repo.AddUserRoleTag(ctx, uid, roleID, "read"))

		// 1) Verify the token (introspection) → identifies the subject.
		r := do(http.MethodGet, "/v1/auth/token/info", nil, nil)
		var info struct {
			Subject string `json:"subject"`
			Typ     string `json:"typ"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&info))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.Equal(t, uid.String(), info.Subject)
		require.Equal(t, "access", info.Typ)

		// 2) Authorize by role.
		r = do(http.MethodGet, "/v1/me/has-role?role_name=gate-role", nil, nil)
		var has map[string]bool
		require.NoError(t, json.NewDecoder(r.Body).Decode(&has))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.True(t, has["has_role"])

		r = do(http.MethodGet, "/v1/me/has-role?role_name=not-a-role", nil, nil)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&has))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.False(t, has["has_role"])

		// A downstream service can perform the same checks using only the
		// caller's human access token in JSON; no bearer header or user ID is
		// accepted by these endpoints.
		r, err = client.Post(base+"/v1/auth/has-role", "application/json", strings.NewReader(fmt.Sprintf(`{"token":%q,"role_name":"gate-role"}`, tokOut.AccessToken)))
		require.NoError(t, err)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&has))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.True(t, has["has_role"])

		var tagged map[string]bool
		r, err = client.Post(base+"/v1/auth/has-role-with-tag", "application/json", strings.NewReader(fmt.Sprintf(`{"token":%q,"role_name":"gate-role","tag":"READ"}`, tokOut.AccessToken)))
		require.NoError(t, err)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&tagged))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.True(t, tagged["has_role_with_tag"])

		r, err = client.Post(base+"/v1/auth/has-role", "application/json", strings.NewReader(`{"token":"invalid","role_name":"gate-role"}`))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusUnauthorized, r.StatusCode)

		// The subject is always taken from the signed token. A caller-supplied
		// user_id is rejected rather than silently creating an ambiguous API.
		r, err = client.Post(base+"/v1/auth/has-role", "application/json", strings.NewReader(fmt.Sprintf(`{"token":%q,"role_name":"gate-role","user_id":%q}`, tokOut.AccessToken, uuid.NewString())))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusBadRequest, r.StatusCode)
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

		// Password change requires 2FA: start (emails a code) then submit with it.
		r = do(http.MethodPost, "/v1/auth/password/2fa", nil, nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		_, err = repo.CreateEmailOTP(ctx, uid, domain.OTPPasswordChange, a.IntegrationOTPHash("321321"), time.Now().Add(time.Minute), nil)
		require.NoError(t, err)
		// Wrong 2FA code is rejected.
		r = do(http.MethodPost, "/v1/auth/password", bytes.NewReader([]byte(`{"old_password":"Password-One1!","new_password":"Password-Two2!","code":"000000"}`)), nil)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusUnauthorized, r.StatusCode)
		// Correct 2FA code succeeds.
		_, err = repo.CreateEmailOTP(ctx, uid, domain.OTPPasswordChange, a.IntegrationOTPHash("321321"), time.Now().Add(time.Minute), nil)
		require.NoError(t, err)
		r = do(http.MethodPost, "/v1/auth/password", bytes.NewReader([]byte(`{"old_password":"Password-One1!","new_password":"Password-Two2!","code":"321321"}`)), nil)
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
		banTarget, err := repo.CreateHumanUser(ctx, "ban-http", "ban-http@test.dev", "hash")
		require.NoError(t, err)
		r = do(http.MethodPost, "/v1/admin/users/"+banTarget.String()+"/ban", bytes.NewReader([]byte(`{"reason":"test"}`)), h)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)
		r = do(http.MethodDelete, "/v1/admin/users/"+banTarget.String()+"/ban", nil, h)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)

		superTarget, err := repo.CreateHumanUser(ctx, "super-ban-http", "super-ban-http@test.dev", "hash")
		require.NoError(t, err)
		require.NoError(t, repo.SetSuperuser(ctx, superTarget, true))
		r = do(http.MethodPost, "/v1/admin/users/"+superTarget.String()+"/ban", bytes.NewReader([]byte(`{"reason":"must fail"}`)), h)
		var banErr map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&banErr))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusBadRequest, r.StatusCode)
		require.Equal(t, "cannot ban a superuser", banErr["error"])
		superUser, err := repo.GetUserByID(ctx, superTarget)
		require.NoError(t, err)
		require.Nil(t, superUser.BannedAt)

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

		// Cross-service role checks authorize a human access token, never a
		// service token, even though token introspection accepts both kinds.
		r, err = client.Post(base+"/v1/auth/has-role", "application/json",
			strings.NewReader(fmt.Sprintf(`{"token":%q,"role_name":"gate-role"}`, sat)))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusUnauthorized, r.StatusCode)

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

		// With no grace period in this test, rotation makes the old human token
		// stale immediately and the public authorization endpoint signals why.
		r, err = client.Post(base+"/v1/auth/has-role", "application/json",
			strings.NewReader(fmt.Sprintf(`{"token":%q,"role_name":"gate-role"}`, tokOut.AccessToken)))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusUnauthorized, r.StatusCode)
		require.Equal(t, "1", r.Header.Get("X-Token-Stale"))
	})

	t.Run("password_reset_public", func(t *testing.T) {
		// Unknown login: 200 with no email (no enumeration).
		r, err := client.Post(base+"/v1/auth/password/reset/start", "application/json",
			strings.NewReader(`{"login":"ghost-nobody"}`))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)

		// Missing login → 400.
		r, err = client.Post(base+"/v1/auth/password/reset/start", "application/json", strings.NewReader(`{}`))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusBadRequest, r.StatusCode)

		// Real user: start, then complete with an injected OTP.
		r, err = client.Post(base+"/v1/auth/password/reset/start", "application/json",
			strings.NewReader(`{"login":"httpuser"}`))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)

		_, _, err = repo.IssuePasswordResetOTP(ctx, uid, a.IntegrationOTPHash("246810"), time.Now(), time.Now().Add(time.Minute), 0)
		require.NoError(t, err)

		// Wrong code → 401.
		r, err = client.Post(base+"/v1/auth/password/reset/complete", "application/json",
			strings.NewReader(`{"login":"httpuser","code":"000000","new_password":"Reset!Pass01"}`))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusUnauthorized, r.StatusCode)

		// Correct code → 204.
		r, err = client.Post(base+"/v1/auth/password/reset/complete", "application/json",
			strings.NewReader(`{"login":"httpuser","code":"246810","new_password":"Reset!Pass01"}`))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusNoContent, r.StatusCode)
	})

	t.Run("magic_link_login", func(t *testing.T) {
		// Unknown login: 200 with no email.
		r, err := client.Post(base+"/v1/auth/login/magic-link", "application/json", strings.NewReader(`{"login":"ghost-nobody"}`))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)

		// Missing login → 400.
		r, err = client.Post(base+"/v1/auth/login/magic-link", "application/json", strings.NewReader(`{}`))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusBadRequest, r.StatusCode)

		// Real user: request a link (the email is sent to Mailpit), then inject a
		// known token and complete the passwordless login.
		r, err = client.Post(base+"/v1/auth/login/magic-link", "application/json", strings.NewReader(`{"login":"httpuser"}`))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)

		token := hex.EncodeToString([]byte("magic-token-0123456789-abcdef!!"))
		_, err = repo.InsertMagicLink(ctx, a.IntegrationMagicHash(token), uid, time.Now().Add(time.Minute))
		require.NoError(t, err)

		// Bad token → 401.
		r, err = client.Post(base+"/v1/auth/login/magic-link/verify", "application/json",
			strings.NewReader(`{"token":"nope","device_id":"dev-magic"}`))
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusUnauthorized, r.StatusCode)

		// Valid token → 200 with cookies + tokens.
		r, err = client.Post(base+"/v1/auth/login/magic-link/verify", "application/json",
			strings.NewReader(fmt.Sprintf(`{"token":%q,"device_id":"dev-magic","device_label":"b"}`, token)))
		require.NoError(t, err)
		var out struct {
			AccessToken string `json:"access_token"`
			CSRFToken   string `json:"csrf_token"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&out))
		require.NoError(t, r.Body.Close())
		require.Equal(t, http.StatusOK, r.StatusCode)
		require.NotEmpty(t, out.AccessToken)
		require.NotEmpty(t, out.CSRFToken)
	})
}
