package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/olegkapshai/auth-master/examples/internal/authz"
	"github.com/stretchr/testify/require"
)

func TestDeploymentHealthcheckRouteMatchesComposeProbe(t *testing.T) {
	compose, err := os.ReadFile("docker-compose.yml")
	require.NoError(t, err)
	require.Contains(t, string(compose), "http://localhost:8092/healthz")

	response := httptest.NewRecorder()
	deploymentApp{checker: panicChecker{}}.routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	require.Equal(t, http.StatusNoContent, response.Code)
	require.Empty(t, response.Body.String())
}

func TestDeploymentPageExplainsAuthorizationInputs(t *testing.T) {
	response := httptest.NewRecorder()
	deploymentApp{checker: panicChecker{}}.routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `<html lang="en">`)
	require.Contains(t, response.Body.String(), "<h1>Deployment authorization</h1>")
	require.Contains(t, response.Body.String(), `<meta name="viewport" content="width=device-width, initial-scale=1">`)
	require.Contains(t, response.Body.String(), `id="examples-ui"`)
	require.Contains(t, response.Body.String(), `.page-shell`)
	require.Contains(t, response.Body.String(), `data-ui="page-shell"`)
	require.Contains(t, response.Body.String(), `data-ui="card"`)
	for _, testID := range []string{"deployment-card", "token", "slug", "deploy", "delete", "result"} {
		require.Contains(t, response.Body.String(), `data-testid="`+testID+`"`)
	}
	require.Contains(t, response.Body.String(), `aria-live="polite"`)
	require.Contains(t, response.Body.String(), `data-testid="personas-card"`)
	require.Contains(t, response.Body.String(), "make -C examples token EXAMPLE=deployment-api")
	require.Contains(t, response.Body.String(), "Allowed — this persona may")
	require.Contains(t, response.Body.String(), "it does not deploy real software")
}

func TestDeploymentRoleMatrixOverHTTPWire(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/has-role", r.URL.Path)
		var body struct {
			Token string `json:"token"`
			Role  string `json:"role_name"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		allowed := map[string]map[string]bool{
			"global":        {"deploy.global-admin": true},
			"developer":     {"deploy.developer": true},
			"billing-admin": {"deploy.app.billing.admin": true},
		}[body.Token][body.Role]
		_ = json.NewEncoder(w).Encode(map[string]bool{"has_role": allowed})
	}))
	t.Cleanup(authServer.Close)
	app := deploymentApp{checker: authz.HTTPChecker{BaseURL: authServer.URL}}.routes()

	tests := []struct {
		method, target, token string
		status                int
	}{
		{http.MethodPost, "/apps/billing/deploy", "global", http.StatusNoContent},
		{http.MethodPost, "/apps/billing/deploy", "developer", http.StatusNoContent},
		{http.MethodPost, "/apps/billing/deploy", "billing-admin", http.StatusNoContent},
		{http.MethodDelete, "/apps/billing", "developer", http.StatusForbidden},
		{http.MethodDelete, "/apps/other", "billing-admin", http.StatusForbidden},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.target, nil)
		req.Header.Set("Authorization", "Bearer "+tt.token)
		response := httptest.NewRecorder()
		app.ServeHTTP(response, req)
		require.Equal(t, tt.status, response.Code, "%s", tt.target)
	}
}

func TestDeploymentRejectsUnsafeSlugBeforeAuth(t *testing.T) {
	app := deploymentApp{checker: panicChecker{}}.routes()
	request := httptest.NewRequest(http.MethodPost, "/apps/INVALID/deploy", nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code)
}

type panicChecker struct{}

func (panicChecker) HasRole(context.Context, string, string) (bool, error) {
	panic("authorization must not be called")
}
