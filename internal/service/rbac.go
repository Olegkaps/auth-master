package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
)

func (a *Auth) IsSuperuser(ctx context.Context, userID uuid.UUID) (bool, error) {
	u, err := a.repo.GetUserByID(ctx, userID)
	if err != nil || u == nil {
		return false, err
	}
	return u.Superuser, nil
}

func (a *Auth) UserHasRoleName(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	return a.repo.UserHasRoleName(ctx, userID, roleName, time.Now())
}

func (a *Auth) IsRoleAdmin(ctx context.Context, userID, roleID uuid.UUID) (bool, error) {
	lvl, ok, err := a.repo.GetUserRoleLevel(ctx, userID, roleID, time.Now())
	if err != nil || !ok {
		return false, err
	}
	return lvl == domain.RoleRoleAdmin, nil
}

func (a *Auth) CanAssignRole(ctx context.Context, actorID, roleID uuid.UUID) (bool, error) {
	su, err := a.IsSuperuser(ctx, actorID)
	if err != nil {
		return false, err
	}
	if su {
		return true, nil
	}
	return a.IsRoleAdmin(ctx, actorID, roleID)
}

func (a *Auth) CanViewUserRoles(ctx context.Context, actorID, targetID uuid.UUID) (bool, error) {
	if actorID == targetID {
		return true, nil
	}
	su, err := a.IsSuperuser(ctx, actorID)
	if err != nil {
		return false, err
	}
	if su {
		return true, nil
	}
	// role admins can view members of their roles — simplified: super only for others
	return false, nil
}
