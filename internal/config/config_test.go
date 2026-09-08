package config

import (
	"os"
	"testing"
	"time"
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
	if c.OTPMaxAttempts != 5 || c.OTPResetMinInterval.String() != "1m0s" {
		t.Fatalf("unexpected OTP limits: attempts=%d interval=%s", c.OTPMaxAttempts, c.OTPResetMinInterval)
	}
	if c.SMTPTimeout != 5*time.Second {
		t.Fatalf("unexpected SMTP timeout: %s", c.SMTPTimeout)
	}
	if c.PublicMailWorkers != 2 || c.PublicMailQueueSize != 64 || c.PublicMailJobTimeout != 10*time.Second {
		t.Fatalf("unexpected public mail queue config: workers=%d size=%d timeout=%s", c.PublicMailWorkers, c.PublicMailQueueSize, c.PublicMailJobTimeout)
	}
	if c.RegistrationOpen || c.SkipLoginOTP {
		t.Fatalf("development auth flags must default off: registration_open=%t skip_login_otp=%t", c.RegistrationOpen, c.SkipLoginOTP)
	}
}

func TestLoadDevelopmentAuthFlags(t *testing.T) {
	t.Setenv("REGISTRATION_OPEN", "true")
	t.Setenv("SKIP_LOGIN_OTP", "true")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.RegistrationOpen || !c.SkipLoginOTP {
		t.Fatalf("flags were not loaded: registration_open=%t skip_login_otp=%t", c.RegistrationOpen, c.SkipLoginOTP)
	}
}

func TestLoadRejectsNonPositiveSMTPTimeout(t *testing.T) {
	t.Setenv("SMTP_TIMEOUT", "0s")
	_, err := Load()
	if err == nil || err.Error() != "SMTP_TIMEOUT must be positive" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsInvalidPublicMailQueueConfiguration(t *testing.T) {
	for _, test := range []struct {
		name, key, value, want string
	}{
		{"workers", "PUBLIC_MAIL_WORKERS", "0", "PUBLIC_MAIL_WORKERS must be positive"},
		{"capacity", "PUBLIC_MAIL_QUEUE_SIZE", "-1", "PUBLIC_MAIL_QUEUE_SIZE must be positive"},
		{"timeout", "PUBLIC_MAIL_JOB_TIMEOUT", "0s", "PUBLIC_MAIL_JOB_TIMEOUT must be positive"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.key, test.value)
			_, err := Load()
			if err == nil || err.Error() != test.want {
				t.Fatalf("unexpected error: %v", err)
			}
		})
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

func TestLoadGRPCConfiguration(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if c.GRPCAddr != ":9090" || c.GRPCReflection || c.GRPCMaxReceiveBytes != 4*1024*1024 || c.GRPCMaxSendBytes != 4*1024*1024 {
			t.Fatalf("unexpected gRPC defaults: %+v", c)
		}
	})
	t.Run("tls pair required", func(t *testing.T) {
		t.Setenv("GRPC_TLS_CERT_FILE", "/tmp/cert.pem")
		t.Setenv("GRPC_TLS_KEY_FILE", "")
		if _, err := Load(); err == nil {
			t.Fatal("expected TLS pair validation error")
		}
	})
	t.Run("positive limits required", func(t *testing.T) {
		t.Setenv("GRPC_MAX_RECEIVE_BYTES", "0")
		if _, err := Load(); err == nil {
			t.Fatal("expected message size validation error")
		}
	})
}

func TestLoadRejectsNonPositiveMaxSessionsPerUser(t *testing.T) {
	for _, value := range []string{"0", "-1"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("MAX_SESSIONS_PER_USER", value)
			_, err := Load()
			if err == nil {
				t.Fatalf("expected MAX_SESSIONS_PER_USER=%s to be rejected", value)
			}
			if err.Error() != "MAX_SESSIONS_PER_USER must be positive" {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestLoadRequiresBootstrapServiceCredentialPair(t *testing.T) {
	t.Run("login only", func(t *testing.T) {
		t.Setenv("BOOTSTRAP_SUPERUSER_SERVICE_LOGIN", "demo-seeder")
		t.Setenv("BOOTSTRAP_SUPERUSER_SERVICE_SECRET", "")
		_, err := Load()
		if err == nil || err.Error() != "BOOTSTRAP_SUPERUSER_SERVICE_LOGIN and BOOTSTRAP_SUPERUSER_SERVICE_SECRET must be set together" {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("secret only", func(t *testing.T) {
		t.Setenv("BOOTSTRAP_SUPERUSER_SERVICE_LOGIN", "")
		t.Setenv("BOOTSTRAP_SUPERUSER_SERVICE_SECRET", "Demo-Service-Secret1!")
		_, err := Load()
		if err == nil || err.Error() != "BOOTSTRAP_SUPERUSER_SERVICE_LOGIN and BOOTSTRAP_SUPERUSER_SERVICE_SECRET must be set together" {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("pair", func(t *testing.T) {
		t.Setenv("BOOTSTRAP_SUPERUSER_SERVICE_LOGIN", "demo-seeder")
		t.Setenv("BOOTSTRAP_SUPERUSER_SERVICE_SECRET", "Demo-Service-Secret1!")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.BootstrapSuperuserServiceLogin != "demo-seeder" || cfg.BootstrapSuperuserServiceSecret == "" {
			t.Fatalf("unexpected bootstrap service config: %+v", cfg)
		}
	})
}
