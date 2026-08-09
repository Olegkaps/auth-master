package demoseed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlansExposeCompleteDemoPersonaMatrices(t *testing.T) {
	tests := []struct {
		example string
		keys    []string
		grants  int
	}{
		{"deployment-api", []string{"global", "developer", "billing", "stranger"}, 3},
		{"support-desk", []string{"owner", "agent", "admin", "stranger"}, 2},
		{"minio-storage", []string{"owner", "reader", "writer", "admin", "stranger"}, 0},
	}
	for _, test := range tests {
		t.Run(test.example, func(t *testing.T) {
			plan, err := PlanFor(test.example)
			require.NoError(t, err)
			require.Len(t, plan.Grants, test.grants)
			for _, key := range test.keys {
				persona, ok := plan.Persona(key)
				require.True(t, ok, key)
				require.NotEmpty(t, persona.Login)
				require.NotEmpty(t, persona.Email)
				require.NotEmpty(t, persona.Capabilities)
				require.Equal(t, DemoPassword, persona.Credentials().Password)
			}
		})
	}
}

func TestSeederDoesNotRetainServiceTokens(t *testing.T) {
	_, retained := reflect.TypeOf(Seeder{}).FieldByName("token")
	require.False(t, retained, "service JWTs must be minted and discarded per privileged action")
}

func TestSeederDoesNotFollowRedirectsWithHumanTokens(t *testing.T) {
	t.Parallel()
	leaked := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/leak" {
			leaked = true
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/leak", http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	seeder := Seeder{config: Config{AppURL: server.URL}}
	err := seeder.appJSONWithToken(context.Background(), http.MethodPost, "/start", map[string]string{
		"AccessToken": "human-token",
	}, "human-token", nil, http.StatusOK)
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("appJSONWithToken redirect error = %v, want status 307", err)
	}
	if leaked {
		t.Fatal("human token followed a redirect")
	}
}

func TestPlanRejectsUnknownExampleAndPersona(t *testing.T) {
	_, err := PlanFor("unknown")
	require.ErrorContains(t, err, "unsupported example")
	plan, err := PlanFor("deployment-api")
	require.NoError(t, err)
	_, ok := plan.Persona("unknown")
	require.False(t, ok)
}
