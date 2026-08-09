package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckAcceptsOnlyHealthyHTTPResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthy" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	require.NoError(t, check(server.URL+"/healthy"))
	require.Error(t, check(server.URL+"/unhealthy"))
	require.Error(t, check("http://127.0.0.1:1"))
}
