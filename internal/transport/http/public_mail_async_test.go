package httptransport

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/olegkapshai/auth-master/internal/config"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/olegkapshai/auth-master/internal/service"
	"github.com/stretchr/testify/require"
)

type blockedHTTPPublicMailRepo struct {
	repository.Repository
	started chan struct{}
	release chan struct{}
}

func (r *blockedHTTPPublicMailRepo) GetHumanUserByLoginOrEmail(ctx context.Context, _ string) (*domain.User, error) {
	close(r.started)
	select {
	case <-r.release:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type noOpHTTPMailer struct{}

func (noOpHTTPMailer) Send(context.Context, []string, string, string) error { return nil }

func TestPublicMailHTTPAdaptersReturnWhilePrivateLookupIsBlocked(t *testing.T) {
	for _, path := range []string{"/v1/auth/login/magic-link", "/v1/auth/password/reset/start"} {
		t.Run(path, func(t *testing.T) {
			key := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
			cfg := &config.Config{SigningKeyMasterKey: key, PasswordHistoryEncryptionKey: key, PublicMailWorkers: 1, PublicMailQueueSize: 1, PublicMailJobTimeout: time.Second}
			repo := &blockedHTTPPublicMailRepo{started: make(chan struct{}), release: make(chan struct{})}
			auth, err := service.NewAuth(cfg, repo, noOpHTTPMailer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			require.NoError(t, err)
			server := httptest.NewServer(NewServer(cfg, auth, repo, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
			defer server.Close()
			returned := make(chan *http.Response, 1)
			go func() {
				resp, _ := http.Post(server.URL+path, "application/json", strings.NewReader(`{"login":"blocked@example.test"}`))
				returned <- resp
			}()
			<-repo.started
			select {
			case resp := <-returned:
				require.NotNil(t, resp)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				resp.Body.Close()
			case <-time.After(time.Second):
				t.Fatal("HTTP adapter waited for private identity lookup")
			}
			close(repo.release)
			require.NoError(t, auth.Shutdown(context.Background()))
		})
	}
}

func TestPublicMailHTTPAdaptersBoundBodiesAndIdentities(t *testing.T) {
	key := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	cfg := &config.Config{SigningKeyMasterKey: key, PasswordHistoryEncryptionKey: key, PublicMailWorkers: 1, PublicMailQueueSize: 1, PublicMailJobTimeout: time.Second}
	repo := &blockedHTTPPublicMailRepo{started: make(chan struct{}), release: make(chan struct{})}
	auth, err := service.NewAuth(cfg, repo, noOpHTTPMailer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	handler := NewServer(cfg, auth, repo, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()

	for _, path := range []string{"/v1/auth/login/magic-link", "/v1/auth/password/reset/start"} {
		t.Run(path+"/identity", func(t *testing.T) {
			body := `{"login":"` + strings.Repeat("x", service.MaxPublicIdentityBytes+1) + `"}`
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			out := httptest.NewRecorder()
			handler.ServeHTTP(out, req)
			require.Equal(t, http.StatusBadRequest, out.Code)
			require.JSONEq(t, `{"error":"invalid login"}`, out.Body.String())
		})
		t.Run(path+"/body", func(t *testing.T) {
			body := `{"login":"known","padding":"` + strings.Repeat("x", int(publicMailStartBodyMaxBytes)) + `"}`
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			out := httptest.NewRecorder()
			handler.ServeHTTP(out, req)
			require.Equal(t, http.StatusBadRequest, out.Code)
			require.JSONEq(t, `{"error":"invalid json"}`, out.Body.String())
		})
	}
	require.NoError(t, auth.Shutdown(context.Background()))
}
