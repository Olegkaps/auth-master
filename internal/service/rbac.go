package service

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
)

func (a *Auth) IsSuperuser(ctx context.Context, userID uuid.UUID) (bool, error) {
	u, err := a.repo.GetUserByID(ctx, userID)
	if err != nil || u == nil {
		return false, err
	}
	if u.BannedAt != nil {
		return false, ErrBanned
	}
	return u.Superuser, nil
}

func (a *Auth) IsBanned(ctx context.Context, userID uuid.UUID) (bool, error) {
	u, err := a.repo.GetUserByID(ctx, userID)
	if err != nil || u == nil {
		return false, err
	}
	return u.BannedAt != nil, nil
}

// UserHasRoleName reports whether the user holds a role — directly OR via the
// hierarchy: membership in an ancestor role grants all descendant roles. This
// is evaluated live, so it reflects hierarchy changes and roles created after
// the membership was granted.
func (a *Auth) UserHasRoleName(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	if banned, err := a.IsBanned(ctx, userID); err != nil || banned {
		if banned {
			return false, ErrBanned
		}
		return false, err
	}
	role, err := a.repo.GetRoleByName(ctx, roleName)
	if err != nil {
		return false, err
	}
	if role == nil {
		return false, nil
	}
	return a.repo.UserHasEffectiveRole(ctx, userID, role.ID, time.Now())
}

func (a *Auth) UserHasRoleWithTag(ctx context.Context, userID uuid.UUID, roleName, tag string) (bool, error) {
	if banned, err := a.IsBanned(ctx, userID); err != nil || banned {
		if banned {
			return false, ErrBanned
		}
		return false, err
	}
	role, err := a.repo.GetRoleByName(ctx, roleName)
	if err != nil || role == nil {
		return false, err
	}
	return a.repo.UserHasEffectiveRoleTag(ctx, userID, role.ID, strings.ToLower(strings.TrimSpace(tag)), time.Now())
}

// IsRoleAdmin reports whether the user is a role admin of the role OR of any of
// its ancestors — role-admin authority is inherited down the hierarchy.
func (a *Auth) IsRoleAdmin(ctx context.Context, userID, roleID uuid.UUID) (bool, error) {
	if banned, err := a.IsBanned(ctx, userID); err != nil || banned {
		if banned {
			return false, ErrBanned
		}
		return false, err
	}
	return a.repo.UserIsEffectiveRoleAdmin(ctx, userID, roleID, time.Now())
}

// CanMountRole requires management authority over both endpoints to prevent a
// manager from attaching their role below a more privileged hierarchy.
func (a *Auth) CanMountRole(ctx context.Context, actorID, childID, parentID uuid.UUID) (bool, error) {
	if su, err := a.IsSuperuser(ctx, actorID); err != nil || su {
		return su, err
	}
	child, err := a.IsRoleAdmin(ctx, actorID, childID)
	if err != nil || !child {
		return false, err
	}
	return a.IsRoleAdmin(ctx, actorID, parentID)
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

// RequestRoleMembership grants membership immediately when the actor can assign
// the role (superuser or role admin, incl. via the hierarchy), otherwise creates
// a pending request for a manager to decide.
func (a *Auth) RequestRoleMembership(ctx context.Context, actor, target, roleID uuid.UUID) (granted bool, requestID uuid.UUID, err error) {
	canManage, err := a.CanAssignRole(ctx, actor, roleID)
	if err != nil {
		return false, uuid.Nil, err
	}
	if canManage {
		gb := actor
		if err := a.repo.AssignUserRole(ctx, target, roleID, domain.RoleMember, &gb, time.Now(), nil); err != nil {
			return false, uuid.Nil, err
		}
		return true, uuid.Nil, nil
	}
	if actor != target {
		return false, uuid.Nil, ErrForbidden
	}
	id, err := a.repo.CreateRoleRequest(ctx, actor, target, roleID)
	return false, id, err
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
