package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/olegkapshai/auth-master/internal/crypto"
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
