package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSupportPageExplainsAuthorizationInputs(t *testing.T) {
	response := httptest.NewRecorder()
	supportHTTPHandler(nil).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `<html lang="en">`)
	require.Contains(t, response.Body.String(), "<h1>Support desk authorization</h1>")
	require.Contains(t, response.Body.String(), "Ticket UUID")
	require.Contains(t, response.Body.String(), `<meta name="viewport" content="width=device-width, initial-scale=1">`)
	require.Contains(t, response.Body.String(), `id="examples-ui"`)
	require.Contains(t, response.Body.String(), `.page-shell`)
	require.Contains(t, response.Body.String(), `data-ui="page-shell"`)
	require.Contains(t, response.Body.String(), `data-ui="card"`)
	for _, testID := range []string{"support-card", "token", "body", "ticket-id", "create", "get", "result"} {
		require.Contains(t, response.Body.String(), `data-testid="`+testID+`"`)
	}
	require.Contains(t, response.Body.String(), `aria-live="polite"`)
	require.Contains(t, response.Body.String(), `data-testid="personas-card"`)
	require.Contains(t, response.Body.String(), "make -C examples token EXAMPLE=support-desk")
	require.Contains(t, response.Body.String(), "Created ticket ")
	require.Contains(t, response.Body.String(), "/demo/tickets")
}

func TestSupportDemoTicketsExposeOnlyIdempotentFixtures(t *testing.T) {
	store := newTicketStore()
	first := store.create("owner", "seeded", "welcome")
	second := store.create("owner", "changed body is ignored", "welcome")
	require.Equal(t, first.ID, second.ID)
	store.create("owner", "ordinary")

	response := httptest.NewRecorder()
	supportHTTPHandler(nil, store).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/demo/tickets", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), first.ID)
	require.NotContains(t, response.Body.String(), "ordinary")
}
