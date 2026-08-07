package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
)

func requireActiveUser(user *domain.User) error {
	if user == nil {
		return ErrInvalidCredentials
	}
	if user.BannedAt != nil {
		return ErrBanned
	}
	return nil
}

func validateBanTarget(actorID uuid.UUID, target *domain.User) error {
	if target == nil {
		return ErrNotFound
	}
	if actorID == target.ID {
		return ErrCannotBanSelf
	}
	if target.Superuser {
		return ErrCannotBanSuperuser
	}
	return nil
}

// BanUser permits only an active superuser to ban a non-superuser account.
func (a *Auth) BanUser(ctx context.Context, actorID, targetID uuid.UUID, reason string) error {
	allowed, err := a.IsSuperuser(ctx, actorID)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrForbidden
	}
	target, err := a.repo.GetUserByID(ctx, targetID)
	if err != nil {
		return err
	}
	if err := validateBanTarget(actorID, target); err != nil {
		return err
	}
	return a.repo.SetUserBan(ctx, targetID, &actorID, reason)
}

// UnbanUser keeps the same superuser-only boundary and existence checks as ban.
func (a *Auth) UnbanUser(ctx context.Context, actorID, targetID uuid.UUID) error {
	allowed, err := a.IsSuperuser(ctx, actorID)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrForbidden
	}
	target, err := a.repo.GetUserByID(ctx, targetID)
	if err != nil {
		return err
	}
	if target == nil {
		return ErrNotFound
	}
	return a.repo.SetUserBan(ctx, targetID, nil, "")
}
