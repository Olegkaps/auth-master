package httptransport

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/olegkapshai/auth-master/internal/config"
	"github.com/stretchr/testify/require"
)

func TestHealthz(t *testing.T) {
	k := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	cfg := &config.Config{
		PasswordHistoryEncryptionKey: k,
		SigningKeyMasterKey:          k,
		CORSAllowedOrigins:           []string{"http://localhost:5173"},
	}
	s := NewServer(cfg, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestRefreshCredentialPrecedesCookieModeCSRF(t *testing.T) {
	k := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	cfg := &config.Config{
		PasswordHistoryEncryptionKey: k,
		SigningKeyMasterKey:          k,
		CORSAllowedOrigins:           []string{"http://localhost:5173"},
		CSRFHeaderName:               "X-CSRF-Token",
		RefreshCookieName:            "refresh_token",
	}
	s := NewServer(cfg, nil, nil, nil)
	t.Run("no credential", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		require.Equal(t, http.StatusUnauthorized, w.Code)
	})
	t.Run("ambient cookie without CSRF", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "ambient"})
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		require.Equal(t, http.StatusForbidden, w.Code)
	})
}
