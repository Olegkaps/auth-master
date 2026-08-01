package config

import (
	"os"
	"testing"
)

func TestLoad_defaultCryptoKeys(t *testing.T) {
	_ = os.Unsetenv("PASSWORD_HISTORY_ENCRYPTION_KEY")
	_ = os.Unsetenv("SIGNING_KEY_MASTER_KEY")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// Defaults are long hex strings (same length as TestLoad_ok fixture).
	if len(c.PasswordHistoryEncryptionKey) < 64 || len(c.SigningKeyMasterKey) < 64 {
		t.Fatalf("expected non-trivial hex defaults, got %d / %d",
			len(c.PasswordHistoryEncryptionKey), len(c.SigningKeyMasterKey))
	}
}

func TestLoad_ok(t *testing.T) {
	// 32-byte keys as hex
	k := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	t.Setenv("PASSWORD_HISTORY_ENCRYPTION_KEY", k)
	t.Setenv("SIGNING_KEY_MASTER_KEY", k)
	t.Cleanup(func() {
		_ = os.Unsetenv("PASSWORD_HISTORY_ENCRYPTION_KEY")
		_ = os.Unsetenv("SIGNING_KEY_MASTER_KEY")
	})
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxSessionsPerUser != 10 {
		t.Fatal(c.MaxSessionsPerUser)
	}
}

func TestLoad_HTTPAddrAndCORS(t *testing.T) {
	t.Setenv("HTTP_ADDR", ":9999")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://a.example,https://b.example")
	t.Cleanup(func() {
		_ = os.Unsetenv("HTTP_ADDR")
		_ = os.Unsetenv("CORS_ALLOWED_ORIGINS")
	})
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPAddr != ":9999" {
		t.Fatalf("HTTPAddr: %q", c.HTTPAddr)
	}
	if len(c.CORSAllowedOrigins) != 2 || c.CORSAllowedOrigins[0] != "https://a.example" {
		t.Fatalf("CORS: %#v", c.CORSAllowedOrigins)
	}
}
