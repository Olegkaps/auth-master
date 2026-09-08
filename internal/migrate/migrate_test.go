package migrate

import (
	"strings"
	"testing"
)

func TestOpenDoesNotExposeDSNCredentials(t *testing.T) {
	const sentinel = "DATABASE-SECRET-SENTINEL"
	_, err := Open("postgres://user:" + sentinel + "@%invalid-host/database")
	if err == nil {
		t.Fatal("expected malformed DSN to fail")
	}
	if strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), "%invalid-host") {
		t.Fatalf("database error exposed DSN details: %q", err)
	}
	if err.Error() != "open PostgreSQL database failed" {
		t.Fatalf("unexpected generic error: %q", err)
	}
}
