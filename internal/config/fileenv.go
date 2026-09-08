package config

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const maxFileEnvironmentValue = 64 << 10

// EnvOrFile resolves NAME or NAME_FILE without ever placing file-backed
// secret contents in the process environment. Setting both forms is rejected
// so deployment mistakes cannot silently select the less secure value.
func EnvOrFile(name, fallback string) (string, error) {
	direct, directSet := os.LookupEnv(name)
	fileName := name + "_FILE"
	path, fileSet := os.LookupEnv(fileName)
	if directSet && fileSet {
		return "", fmt.Errorf("%s and %s cannot both be set", name, fileName)
	}
	if !fileSet {
		if directSet {
			return direct, nil
		}
		return fallback, nil
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("%s must name a readable file", fileName)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", fileName, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxFileEnvironmentValue+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", fileName, err)
	}
	if len(data) > maxFileEnvironmentValue {
		return "", fmt.Errorf("%s exceeds %d bytes", fileName, maxFileEnvironmentValue)
	}
	value := strings.TrimRight(string(data), "\r\n")
	if value == "" {
		return "", fmt.Errorf("%s is empty", fileName)
	}
	if strings.ContainsRune(value, '\x00') {
		return "", fmt.Errorf("%s contains a NUL byte", fileName)
	}
	return value, nil
}

func applyFileEnvironment(c *Config) error {
	for _, item := range []struct {
		name  string
		value *string
	}{
		{name: "DATABASE_URL", value: &c.DatabaseURL},
		{name: "SMTP_USER", value: &c.SMTPUser},
		{name: "SMTP_PASSWORD", value: &c.SMTPPassword},
		{name: "BOOTSTRAP_SUPERUSER_PASSWORD", value: &c.BootstrapSuperuserPassword},
		{name: "BOOTSTRAP_SUPERUSER_SERVICE_SECRET", value: &c.BootstrapSuperuserServiceSecret},
		{name: "PASSWORD_HISTORY_ENCRYPTION_KEY", value: &c.PasswordHistoryEncryptionKey},
		{name: "SIGNING_KEY_MASTER_KEY", value: &c.SigningKeyMasterKey},
		{name: "REGISTRATION_INVITE_CALLBACK_URL", value: &c.RegistrationInviteCallbackURL},
		{name: "MAGIC_LINK_CALLBACK_URL", value: &c.MagicLinkCallbackURL},
	} {
		resolved, err := EnvOrFile(item.name, *item.value)
		if err != nil {
			return err
		}
		*item.value = resolved
	}
	return nil
}
