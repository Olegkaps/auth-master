package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type subjectVerifierFunc func(context.Context, string) (string, error)

func (f subjectVerifierFunc) VerifySubject(ctx context.Context, token string) (string, error) {
	return f(ctx, token)
}

func TestJWTSubjectVerifierRejectsMalformedTokensBeforeUpstream(t *testing.T) {
	called := false
	verifier := JWTSubjectVerifier{Verifier: subjectVerifierFunc(func(context.Context, string) (string, error) {
		called = true
		return "subject", nil
	})}

	for _, token := range []string{"not-a-valid-access-token", "e30.e30", "%%%.e30.c2ln", "e30.W10.c2ln"} {
		_, err := verifier.VerifySubject(t.Context(), token)
		require.Equal(t, codes.Unauthenticated, status.Code(err), token)
	}
	require.False(t, called)
}

func TestJWTSubjectVerifierForwardsStructurallyValidTokens(t *testing.T) {
	const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"
	verifier := JWTSubjectVerifier{Verifier: subjectVerifierFunc(func(_ context.Context, got string) (string, error) {
		require.Equal(t, token, got)
		return "subject", nil
	})}

	subject, err := verifier.VerifySubject(t.Context(), token)
	require.NoError(t, err)
	require.Equal(t, "subject", subject)
}

func TestBearerToken(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer human-token")
	token, err := BearerToken(request)
	require.NoError(t, err)
	require.Equal(t, "human-token", token)

	request.Header.Add("Authorization", "Bearer second")
	_, err = BearerToken(request)
	require.ErrorIs(t, err, ErrMissingBearer)
}

func TestHTTPCheckerUsesTokenAsRequestData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/has-role-with-tag", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"has_role_with_tag":true}`))
	}))
	t.Cleanup(server.Close)

	allowed, err := (HTTPChecker{BaseURL: server.URL}).HasRoleWithTag(t.Context(), "human-token", "folder", "read")
	require.NoError(t, err)
	require.True(t, allowed)
}

func TestHTTPCheckerRejectsRedirectsAndTrailingJSON(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.invalid/leak", http.StatusTemporaryRedirect)
		}))
		t.Cleanup(server.Close)
		_, err := (HTTPChecker{BaseURL: server.URL}).HasRole(t.Context(), "secret-token", "role")
		require.ErrorContains(t, err, "status 307")
	})

	t.Run("trailing value", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"has_role":true} {"has_role":false}`))
		}))
		t.Cleanup(server.Close)
		_, err := (HTTPChecker{BaseURL: server.URL}).HasRole(t.Context(), "token", "role")
		require.ErrorContains(t, err, "trailing JSON")
	})
}

func TestHTTPCheckerAppliesDeadline(t *testing.T) {
	canceled := make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		close(canceled)
		return nil, request.Context().Err()
	})}
	_, err := (HTTPChecker{BaseURL: "http://auth-master.test", Client: client, Timeout: time.Millisecond}).HasRole(t.Context(), "token", "role")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("transport did not observe request cancellation")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
