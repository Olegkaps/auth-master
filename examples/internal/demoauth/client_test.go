package demoauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHumanTokenUsesPasswordOTPAndReturnsAccessToken(t *testing.T) {
	var loginStarted atomic.Bool
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/login":
			loginStarted.Store(true)
			_ = json.NewEncoder(w).Encode(map[string]string{"login_challenge": "challenge"})
		case "/v1/auth/login/verify-otp":
			var body map[string]string
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			require.Equal(t, "654321", body["code"])
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "human-token"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(auth.Close)
	mail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/messages" {
			messages := []any{map[string]any{"ID": "old-message", "To": []any{map[string]string{"Address": "person@example.test"}}}}
			if loginStarted.Load() {
				messages = append(messages, map[string]any{"ID": "new-message", "To": []any{map[string]string{"Address": "person@example.test"}}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": messages})
			return
		}
		code := "111111"
		if r.URL.Path == "/api/v1/message/new-message" {
			code = "654321"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"Text": "Your code is " + code + "."})
	}))
	t.Cleanup(mail.Close)

	token, err := (Client{AuthURL: auth.URL, MailURL: mail.URL}).HumanToken(context.Background(), Credentials{
		Login: "person", Email: "person@example.test", Password: "Example!Passw0rd9",
	})
	require.NoError(t, err)
	require.Equal(t, "human-token", token)
}

func TestSixDigitCodeRequiresBoundaries(t *testing.T) {
	require.Equal(t, "123456", sixDigitCode("code 123456 ok"))
	require.Empty(t, sixDigitCode("x1234567y"))
	require.Empty(t, sixDigitCode("no code"))
}

func TestServiceTokenExchangesConfiguredCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/service-token", r.URL.Path)
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "example-seeder", body["login"])
		require.Equal(t, "secret", body["secret"])
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "service-token"})
	}))
	t.Cleanup(server.Close)
	token, err := (Client{AuthURL: server.URL}).ServiceToken(context.Background(), "example-seeder", "secret")
	require.NoError(t, err)
	require.Equal(t, "service-token", token)
}

func TestServiceTokenDoesNotFollowRedirectsWithCredentials(t *testing.T) {
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

	_, err := (Client{AuthURL: server.URL}).ServiceToken(context.Background(), "seeder", "secret")
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("ServiceToken redirect error = %v, want status 307", err)
	}
	if leaked {
		t.Fatal("service credentials followed a redirect")
	}
}
