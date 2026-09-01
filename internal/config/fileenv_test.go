package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvOrFile(t *testing.T) {
	t.Run("fallback and direct", func(t *testing.T) {
		const name = "AUTH_MASTER_TEST_VALUE"
		if value, err := EnvOrFile(name, "fallback"); err != nil || value != "fallback" {
			t.Fatalf("fallback: value=%q err=%v", value, err)
		}
		t.Setenv(name, "direct value")
		if value, err := EnvOrFile(name, "fallback"); err != nil || value != "direct value" {
			t.Fatalf("direct: value=%q err=%v", value, err)
		}
	})

	t.Run("file removes only conventional final newline", func(t *testing.T) {
		const name = "AUTH_MASTER_TEST_FILE_VALUE"
		path := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(path, []byte("  secret with spaces  \r\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(name+"_FILE", path)
		value, err := EnvOrFile(name, "fallback")
		if err != nil {
			t.Fatal(err)
		}
		if value != "  secret with spaces  " {
			t.Fatalf("value = %q", value)
		}
	})

	t.Run("direct and file conflict", func(t *testing.T) {
		const name = "AUTH_MASTER_TEST_CONFLICT"
		path := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(path, []byte("file"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(name, "direct")
		t.Setenv(name+"_FILE", path)
		if _, err := EnvOrFile(name, ""); err == nil || !strings.Contains(err.Error(), "cannot both be set") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	for _, test := range []struct {
		name string
		data []byte
		want string
	}{
		{name: "empty", data: []byte("\n"), want: "is empty"},
		{name: "nul byte", data: []byte("secret\x00suffix\n"), want: "contains a NUL byte"},
		{name: "too large", data: []byte(strings.Repeat("x", maxFileEnvironmentValue+1)), want: "exceeds"},
	} {
		t.Run(test.name, func(t *testing.T) {
			const name = "AUTH_MASTER_TEST_INVALID_FILE"
			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(name+"_FILE", path)
			if _, err := EnvOrFile(name, ""); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestLoadFileBackedSecrets(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL":                       "postgres://file-user:file-pass@db/auth?sslmode=require",
		"SMTP_USER":                          "smtp-file-user",
		"SMTP_PASSWORD":                      "smtp-file-password",
		"BOOTSTRAP_SUPERUSER_PASSWORD":       "Bootstrap-File9!",
		"BOOTSTRAP_SUPERUSER_SERVICE_SECRET": "Service-File9!",
		"PASSWORD_HISTORY_ENCRYPTION_KEY":    "file-history-key",
		"SIGNING_KEY_MASTER_KEY":             "file-signing-key",
		"REGISTRATION_INVITE_CALLBACK_URL":   "https://app.example/register",
		"MAGIC_LINK_CALLBACK_URL":            "https://app.example/admit",
	}
	for name, value := range values {
		path := filepath.Join(t.TempDir(), strings.ToLower(name))
		if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(name+"_FILE", path)
	}
	t.Setenv("BOOTSTRAP_SUPERUSER_SERVICE_LOGIN", "file-service")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{
		"DATABASE_URL":                       cfg.DatabaseURL,
		"SMTP_USER":                          cfg.SMTPUser,
		"SMTP_PASSWORD":                      cfg.SMTPPassword,
		"BOOTSTRAP_SUPERUSER_PASSWORD":       cfg.BootstrapSuperuserPassword,
		"BOOTSTRAP_SUPERUSER_SERVICE_SECRET": cfg.BootstrapSuperuserServiceSecret,
		"PASSWORD_HISTORY_ENCRYPTION_KEY":    cfg.PasswordHistoryEncryptionKey,
		"SIGNING_KEY_MASTER_KEY":             cfg.SigningKeyMasterKey,
		"REGISTRATION_INVITE_CALLBACK_URL":   cfg.RegistrationInviteCallbackURL,
		"MAGIC_LINK_CALLBACK_URL":            cfg.MagicLinkCallbackURL,
	}
	for name, want := range values {
		if got[name] != want {
			t.Fatalf("%s = %q, want file value", name, got[name])
		}
	}
}
