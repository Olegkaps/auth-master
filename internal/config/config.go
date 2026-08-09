package config

import (
	"errors"
	"strings"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

// Config is loaded from environment (and optional .env via cleanenv ReadEnv).
type Config struct {
	HTTPAddr              string        `env:"HTTP_ADDR" env-default:":8080"`
	GRPCAddr              string        `env:"GRPC_ADDR" env-default:":9090"`
	GRPCTLSCertFile       string        `env:"GRPC_TLS_CERT_FILE" env-default:""`
	GRPCTLSKeyFile        string        `env:"GRPC_TLS_KEY_FILE" env-default:""`
	GRPCReflection        bool          `env:"GRPC_REFLECTION" env-default:"false"`
	GRPCMaxReceiveBytes   int           `env:"GRPC_MAX_RECEIVE_BYTES" env-default:"4194304"`
	GRPCMaxSendBytes      int           `env:"GRPC_MAX_SEND_BYTES" env-default:"4194304"`
	ShutdownTimeout       time.Duration `env:"SHUTDOWN_TIMEOUT" env-default:"10s"`
	DatabaseURL           string        `env:"DATABASE_URL" env-default:"postgres://auth:auth@localhost:5432/auth?sslmode=disable"`
	LogLevel              string        `env:"LOG_LEVEL" env-default:"info"`
	AccessTokenTTL        time.Duration `env:"ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL       time.Duration `env:"REFRESH_TOKEN_TTL" env-default:"720h"`
	SigningGracePeriod    time.Duration `env:"SIGNING_KEY_GRACE_PERIOD" env-default:"15m"`
	SigningKeyRotateEvery time.Duration `env:"SIGNING_KEY_ROTATE_EVERY" env-default:"0"`
	PasswordMaxAge        time.Duration `env:"PASSWORD_MAX_AGE" env-default:"2160h"`
	PasswordHistoryN      int           `env:"PASSWORD_HISTORY_N" env-default:"10"`
	OTPCodeTTL            time.Duration `env:"OTP_CODE_TTL" env-default:"10m"`
	OTPCodeLength         int           `env:"OTP_CODE_LENGTH" env-default:"6"`
	OTPMaxAttempts        int           `env:"OTP_MAX_ATTEMPTS" env-default:"5"`
	OTPResetMinInterval   time.Duration `env:"OTP_RESET_MIN_INTERVAL" env-default:"1m"`
	MagicLinkTTL          time.Duration `env:"MAGIC_LINK_TTL" env-default:"15m"`
	MaxSessionsPerUser    int           `env:"MAX_SESSIONS_PER_USER" env-default:"10"`
	LoginFailWindow       time.Duration `env:"LOGIN_FAIL_WINDOW" env-default:"15m"`
	LoginFailMax          int           `env:"LOGIN_FAIL_MAX" env-default:"5"`
	LoginLockDuration     time.Duration `env:"LOGIN_LOCK_DURATION" env-default:"30m"`
	NotifyOnFailThreshold int           `env:"LOGIN_NOTIFY_FAIL_THRESHOLD" env-default:"3"`
	SMTPHost              string        `env:"SMTP_HOST" env-default:"localhost"`
	SMTPPort              int           `env:"SMTP_PORT" env-default:"1025"`
	SMTPUser              string        `env:"SMTP_USER" env-default:""`
	SMTPPassword          string        `env:"SMTP_PASSWORD" env-default:""`
	MailFrom              string        `env:"MAIL_FROM" env-default:"auth@localhost"`
	AppPublicURL          string        `env:"APP_PUBLIC_URL" env-default:"http://localhost:8080"`
	// Base URL for one-time registration links shown to admins (usually the SPA origin).
	RegistrationInviteBaseURL string `env:"REGISTRATION_INVITE_BASE_URL" env-default:"http://localhost:5173"`
	// First start: if no human users exist, create this superuser (leave empty to disable).
	BootstrapSuperuserLogin    string `env:"BOOTSTRAP_SUPERUSER_LOGIN" env-default:""`
	BootstrapSuperuserEmail    string `env:"BOOTSTRAP_SUPERUSER_EMAIL" env-default:""`
	BootstrapSuperuserPassword string `env:"BOOTSTRAP_SUPERUSER_PASSWORD" env-default:""`
	// Optional service identity used by demo automation. Both values must be set
	// together; authd validates an existing account instead of silently replacing it.
	BootstrapSuperuserServiceLogin  string `env:"BOOTSTRAP_SUPERUSER_SERVICE_LOGIN" env-default:""`
	BootstrapSuperuserServiceSecret string `env:"BOOTSTRAP_SUPERUSER_SERVICE_SECRET" env-default:""`
	// AES-256: 32 raw bytes as base64 or hex (see internal/crypto/keys.go). Defaults suit local dev only.
	PasswordHistoryEncryptionKey string `env:"PASSWORD_HISTORY_ENCRYPTION_KEY" env-default:"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"`
	SigningKeyMasterKey          string `env:"SIGNING_KEY_MASTER_KEY" env-default:"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"`
	RefreshCookieName            string `env:"REFRESH_COOKIE_NAME" env-default:"refresh_token"`
	CSRFHeaderName               string `env:"CSRF_HEADER_NAME" env-default:"X-CSRF-Token"`
	// Cookie secure flag (false for local dev)
	RefreshCookieSecure bool `env:"REFRESH_COOKIE_SECURE" env-default:"false"`
	// CORS for frontend dev
	CORSAllowedOrigins []string `env:"CORS_ALLOWED_ORIGINS" env-separator:"," env-default:"http://localhost:5173"`
}

func Load() (Config, error) {
	var c Config
	if err := cleanenv.ReadEnv(&c); err != nil {
		return Config{}, err
	}
	if (strings.TrimSpace(c.GRPCTLSCertFile) == "") != (strings.TrimSpace(c.GRPCTLSKeyFile) == "") {
		return Config{}, errors.New("GRPC_TLS_CERT_FILE and GRPC_TLS_KEY_FILE must be set together")
	}
	if c.GRPCMaxReceiveBytes <= 0 || c.GRPCMaxSendBytes <= 0 {
		return Config{}, errors.New("gRPC message size limits must be positive")
	}
	if c.ShutdownTimeout <= 0 {
		return Config{}, errors.New("SHUTDOWN_TIMEOUT must be positive")
	}
	if c.MaxSessionsPerUser <= 0 {
		return Config{}, errors.New("MAX_SESSIONS_PER_USER must be positive")
	}
	serviceLoginSet := strings.TrimSpace(c.BootstrapSuperuserServiceLogin) != ""
	serviceSecretSet := c.BootstrapSuperuserServiceSecret != ""
	if serviceLoginSet != serviceSecretSet {
		return Config{}, errors.New("BOOTSTRAP_SUPERUSER_SERVICE_LOGIN and BOOTSTRAP_SUPERUSER_SERVICE_SECRET must be set together")
	}
	return c, nil
}
