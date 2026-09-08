package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckAcceptsEverySuccessfulHealthStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := check(server.Client(), server.URL); err != nil {
		t.Fatalf("expected 204 health response to pass: %v", err)
	}
}

func TestCheckRejectsUnhealthyStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	if err := check(server.Client(), server.URL); err == nil {
		t.Fatal("expected 503 health response to fail")
	}
}
