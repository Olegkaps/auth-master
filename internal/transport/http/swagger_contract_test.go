package httptransport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/olegkapshai/auth-master/internal/transport/parity"
	"github.com/stretchr/testify/require"
)

func TestGeneratedSwaggerDocumentsCSRFErrorsAndNullableFields(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	require.True(t, ok)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "..", "docs", "swagger.json"))
	require.NoError(t, err)
	var spec map[string]any
	require.NoError(t, json.Unmarshal(raw, &spec))
	paths := spec["paths"].(map[string]any)

	assertConditionalActorCSRF := func(path, method string) {
		t.Helper()
		operation := paths[path].(map[string]any)[method].(map[string]any)
		parameters := operation["parameters"].([]any)
		var csrfHeader map[string]any
		for _, item := range parameters {
			parameter := item.(map[string]any)
			if parameter["name"] == "X-CSRF-Token" && parameter["in"] == "header" {
				csrfHeader = parameter
				break
			}
		}
		require.NotNil(t, csrfHeader, "%s %s must document its conditional double-submit header", method, path)
		require.NotEqual(t, true, csrfHeader["required"], "%s %s must allow verified service actors to omit CSRF", method, path)
		description, _ := csrfHeader["description"].(string)
		require.Contains(t, description, "Required for human access tokens", "%s %s must document the human-token CSRF requirement", method, path)
		require.Contains(t, description, "omitted for verified service tokens", "%s %s must document the service-token exception", method, path)
		responses := operation["responses"].(map[string]any)
		require.Contains(t, responses, "403", "%s %s must document HTTP 403", method, path)
	}

	for _, route := range parity.BusinessRoutes {
		if route.Auth == parity.AuthActor && route.CSRF {
			assertConditionalActorCSRF(route.HTTPPath, strings.ToLower(route.HTTPMethod))
		}
	}

	refresh := paths["/v1/auth/refresh"].(map[string]any)["post"].(map[string]any)
	description := refresh["description"].(string)
	require.Contains(t, description, "body-token mode")
	require.Contains(t, description, "requires no cookie or CSRF")
	require.Contains(t, description, "X-CSRF-Token matching the csrf_token cookie")
	var refreshHeader, refreshBody map[string]any
	for _, rawParameter := range refresh["parameters"].([]any) {
		parameter := rawParameter.(map[string]any)
		switch parameter["name"] {
		case "X-CSRF-Token":
			refreshHeader = parameter
		case "body":
			refreshBody = parameter
		}
	}
	require.NotNil(t, refreshHeader)
	require.NotEqual(t, true, refreshHeader["required"])
	require.Contains(t, refreshHeader["description"], "Required only in cookie mode")
	require.NotNil(t, refreshBody)
	require.NotEqual(t, true, refreshBody["required"])
	require.Contains(t, refreshBody["description"], "omitting refresh_token selects cookie mode")
	refreshResponses := refresh["responses"].(map[string]any)
	require.Contains(t, refreshResponses, "401")
	require.Contains(t, refreshResponses, "403")

	definitions := spec["definitions"].(map[string]any)
	refreshSchema := definitions["httptransport.RefreshRequestBody"].(map[string]any)
	_, hasRequired := refreshSchema["required"]
	require.False(t, hasRequired, "every refresh body field is conditionally optional")
	refreshProperties := refreshSchema["properties"].(map[string]any)
	refreshTokenDescription := refreshProperties["refresh_token"].(map[string]any)["description"].(string)
	require.True(t, strings.Contains(refreshTokenDescription, "body-token mode") && strings.Contains(refreshTokenDescription, "X-CSRF-Token"))
	assertNullable := func(definition, property string) {
		t.Helper()
		properties := definitions[definition].(map[string]any)["properties"].(map[string]any)
		require.Equal(t, true, properties[property].(map[string]any)["x-nullable"], "%s.%s must match runtime null", definition, property)
	}
	assertNullable("httptransport.RolesListResponse", "total")
	assertNullable("httptransport.AdminUsersResponse", "total")
	assertNullable("httptransport.AdminUserRow", "email")
	assertNullable("httptransport.AdminUserRow", "banned_at")
	assertNullable("httptransport.RoleMemberRow", "email")
}
