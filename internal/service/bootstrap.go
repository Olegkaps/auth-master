package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/olegkapshai/auth-master/internal/crypto"
	"github.com/olegkapshai/auth-master/internal/domain"
)

// EnsureBootstrapAdmin creates the first superuser when BOOTSTRAP_SUPERUSER_* is set and there are no human users yet.
func (a *Auth) EnsureBootstrapAdmin(ctx context.Context) error {
	login := strings.TrimSpace(a.cfg.BootstrapSuperuserLogin)
	if login == "" {
		return nil
	}
	n, err := a.repo.CountHumanUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	email := strings.TrimSpace(a.cfg.BootstrapSuperuserEmail)
	if email == "" {
		return fmt.Errorf("BOOTSTRAP_SUPERUSER_EMAIL is required when BOOTSTRAP_SUPERUSER_LOGIN is set")
	}
	pwd := a.cfg.BootstrapSuperuserPassword
	if pwd == "" {
		return fmt.Errorf("BOOTSTRAP_SUPERUSER_PASSWORD is required when BOOTSTRAP_SUPERUSER_LOGIN is set")
	}
	login = normalizeLogin(login)
	hash, err := crypto.HashPassword(pwd)
	if err != nil {
		return err
	}
	id, err := a.repo.CreateHumanUser(ctx, login, email, hash)
	if err != nil {
		return err
	}
	if err := a.repo.SetSuperuser(ctx, id, true); err != nil {
		return err
	}
	return a.appendPasswordHistory(ctx, id, pwd, hash)
}

// EnsureBootstrapSuperuserService reconciles the optional automation identity.
// It never rotates or replaces credentials: an existing login must already be
// an active superuser service with the configured secret.
func (a *Auth) EnsureBootstrapSuperuserService(ctx context.Context) error {
	configuredLogin := strings.TrimSpace(a.cfg.BootstrapSuperuserServiceLogin)
	if configuredLogin == "" {
		return nil
	}
	login, err := validateServiceAccountCredentials(configuredLogin, a.cfg.BootstrapSuperuserServiceSecret)
	if err != nil {
		return err
	}
	existing, err := a.repo.GetUserByLogin(ctx, login)
	if err != nil {
		return err
	}
	if existing != nil {
		return bootstrapSuperuserServiceMatches(existing, a.cfg.BootstrapSuperuserServiceSecret)
	}
	hash, err := crypto.HashSecret(a.cfg.BootstrapSuperuserServiceSecret)
	if err != nil {
		return err
	}
	if _, err := a.repo.CreateServiceUser(ctx, login, hash, true); err == nil {
		return nil
	} else {
		// Another replica may have won the unique-login race. Accept only the
		// exact configured identity; every collision remains a startup failure.
		concurrent, lookupErr := a.repo.GetUserByLogin(ctx, login)
		if lookupErr != nil || concurrent == nil {
			return err
		}
		return bootstrapSuperuserServiceMatches(concurrent, a.cfg.BootstrapSuperuserServiceSecret)
	}
}

func bootstrapSuperuserServiceMatches(user *domain.User, secret string) error {
	if user.Kind != domain.UserService || !user.Superuser || user.ServiceSecretHash == nil || user.BannedAt != nil {
		return fmt.Errorf("bootstrap superuser service login collides with an incompatible account")
	}
	matches, err := crypto.VerifySecret(secret, *user.ServiceSecretHash)
	if err != nil || !matches {
		return fmt.Errorf("bootstrap superuser service credentials do not match the existing account")
	}
	return nil
}
