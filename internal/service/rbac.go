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

// UserHasRoleName reports whether the user holds a role — directly OR via the
// hierarchy: membership in an ancestor role grants all descendant roles. This
// is evaluated live, so it reflects hierarchy changes and roles created after
// the membership was granted.
func (a *Auth) UserHasRoleName(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	role, err := a.repo.GetRoleByName(ctx, roleName)
	if err != nil {
		return false, err
	}
	if role == nil {
		return false, nil
	}
	ancestors, err := a.repo.RoleAncestors(ctx, role.ID)
	if err != nil {
		return false, err
	}
	if len(ancestors) == 0 {
		ancestors = []uuid.UUID{role.ID}
	}
	now := time.Now()
	for _, rid := range ancestors {
		if _, ok, err := a.repo.GetUserRoleLevel(ctx, userID, rid, now); err != nil {
			return false, err
		} else if ok {
			return true, nil
		}
	}
	return false, nil
}

// IsRoleAdmin reports whether the user is a role admin of the role OR of any of
// its ancestors — role-admin authority is inherited down the hierarchy.
func (a *Auth) IsRoleAdmin(ctx context.Context, userID, roleID uuid.UUID) (bool, error) {
	ancestors, err := a.repo.RoleAncestors(ctx, roleID)
	if err != nil {
		return false, err
	}
	if len(ancestors) == 0 {
		ancestors = []uuid.UUID{roleID} // role has no parent chain rows; still check itself
	}
	now := time.Now()
	for _, rid := range ancestors {
		lvl, ok, err := a.repo.GetUserRoleLevel(ctx, userID, rid, now)
		if err != nil {
			return false, err
		}
		if ok && lvl == domain.RoleRoleAdmin {
			return true, nil
		}
	}
	return false, nil
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
