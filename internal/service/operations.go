package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/crypto"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/repository"
)

const (
	maxServiceAccountLoginBytes = 255
	maxServiceSecretBytes       = 1024
)

// validateServiceAccountCredentials is shared by the runtime admin API and
// bootstrap setup so both paths enforce one credential contract.
func validateServiceAccountCredentials(login, secret string) (string, error) {
	login = normalizeLogin(login)
	if login == "" {
		return "", fmt.Errorf("%w: service account login is required", ErrInvalidArgument)
	}
	if len(login) > maxServiceAccountLoginBytes {
		return "", fmt.Errorf("%w: service account login is too long", ErrInvalidArgument)
	}
	if len(secret) > maxServiceSecretBytes {
		return "", fmt.Errorf("%w: service secret is too long", ErrInvalidArgument)
	}
	if err := checkPasswordComplexity(secret); err != nil {
		detail := strings.TrimPrefix(err.Error(), ErrPasswordPolicy.Error()+": ")
		return "", fmt.Errorf("%w: %s", ErrPasswordPolicy, strings.ReplaceAll(detail, "password", "service secret"))
	}
	return login, nil
}

// CreateServiceAccount creates a non-human principal whose service token may
// call AdminService and RoleService. Only an active superuser actor may create
// one; the raw secret is hashed before the atomic persistence operation.
func (a *Auth) CreateServiceAccount(ctx context.Context, actor uuid.UUID, login, secret string, superuser bool) (uuid.UUID, error) {
	ok, err := a.IsSuperuser(ctx, actor)
	if err != nil {
		return uuid.Nil, err
	}
	if !ok {
		return uuid.Nil, ErrForbidden
	}
	login, err = validateServiceAccountCredentials(login, secret)
	if err != nil {
		return uuid.Nil, err
	}
	secretHash, err := crypto.HashSecret(secret)
	if err != nil {
		return uuid.Nil, err
	}
	return a.repo.CreateServiceUser(ctx, login, secretHash, superuser)
}

// The methods in this file are transport-neutral use cases. HTTP and gRPC
// adapters should only validate wire values and convert their results.

func (a *Auth) CurrentUser(ctx context.Context, actor uuid.UUID) (*domain.User, error) {
	u, err := a.repo.GetUserByID(ctx, actor)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrNotFound
	}
	return u, nil
}

func (a *Auth) EffectiveRoleAccess(ctx context.Context, actor uuid.UUID) ([]repository.EffectiveRoleAccess, error) {
	return a.repo.ListEffectiveRoleAccess(ctx, actor, time.Now())
}

func (a *Auth) Sessions(ctx context.Context, actor uuid.UUID) ([]domain.RefreshSession, error) {
	return a.repo.ListRefreshSessions(ctx, actor)
}

func (a *Auth) UsersPage(ctx context.Context, actor uuid.UUID, query string, cursor *repository.PageCursor, size int) ([]domain.User, *repository.PageCursor, *int64, error) {
	ok, err := a.IsSuperuser(ctx, actor)
	if err != nil {
		return nil, nil, nil, err
	}
	if !ok {
		return nil, nil, nil, ErrForbidden
	}
	return a.repo.SearchUsers(ctx, query, cursor, size, cursor == nil)
}

func (a *Auth) RolesPage(ctx context.Context, query string, cursor *repository.PageCursor, size int) ([]domain.Role, *repository.PageCursor, *int64, error) {
	return a.repo.SearchRoles(ctx, query, cursor, size, cursor == nil)
}

func (a *Auth) CreateRole(ctx context.Context, actor uuid.UUID, name, description string, parents []uuid.UUID) (uuid.UUID, error) {
	ok, err := a.IsSuperuser(ctx, actor)
	if err != nil {
		return uuid.Nil, err
	}
	if !ok {
		return uuid.Nil, ErrForbidden
	}
	return a.repo.CreateRoleWithParents(ctx, name, strings.TrimSpace(description), parents)
}

func (a *Auth) DeleteRole(ctx context.Context, actor, role uuid.UUID) error {
	ok, err := a.IsSuperuser(ctx, actor)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return a.repo.DeleteRole(ctx, role)
}

func (a *Auth) SetRoleParent(ctx context.Context, actor, role uuid.UUID, parent *uuid.UUID) error {
	ok, err := a.IsSuperuser(ctx, actor)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return a.repo.SetRoleParent(ctx, role, parent)
}

func (a *Auth) UpdateRoleDescription(ctx context.Context, actor, role uuid.UUID, description string) error {
	superuser, err := a.IsSuperuser(ctx, actor)
	if err != nil {
		return err
	}
	admin, err := a.IsRoleAdmin(ctx, actor, role)
	if err != nil {
		return err
	}
	if !superuser && !admin {
		return ErrForbidden
	}
	return a.repo.UpdateRoleDescription(ctx, role, description)
}

func (a *Auth) Mount(ctx context.Context, actor, role, parent uuid.UUID) error {
	ok, err := a.CanMountRole(ctx, actor, role, parent)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return a.repo.MountRole(ctx, role, parent)
}

func (a *Auth) Unmount(ctx context.Context, actor, role, parent uuid.UUID) error {
	ok, err := a.CanMountRole(ctx, actor, role, parent)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return a.repo.UnmountRole(ctx, role, parent)
}

func (a *Auth) Subgroups(ctx context.Context, role uuid.UUID, recursive bool) ([]domain.Role, error) {
	return a.repo.ListSubroles(ctx, role, recursive)
}

func (a *Auth) ChangeRoleTag(ctx context.Context, actor, role uuid.UUID, tag string, add bool) error {
	ok, err := a.CanAssignRole(ctx, actor, role)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	if add {
		return a.repo.AddRoleTag(ctx, role, tag)
	}
	return a.repo.DeleteRoleTag(ctx, role, tag)
}

func (a *Auth) RenameRoleTag(ctx context.Context, actor, role uuid.UUID, oldTag, newTag string) error {
	ok, err := a.CanAssignRole(ctx, actor, role)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return a.repo.RenameRoleTag(ctx, role, oldTag, newTag)
}

func (a *Auth) RoleMembers(ctx context.Context, actor, role uuid.UUID) ([]repository.RoleMember, error) {
	ok, err := a.CanAssignRole(ctx, actor, role)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrForbidden
	}
	return a.repo.ListRoleMembers(ctx, role, time.Now())
}

func (a *Auth) UserRoles(ctx context.Context, actor, target uuid.UUID) ([]domain.UserRole, error) {
	ok, err := a.CanViewUserRoles(ctx, actor, target)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrForbidden
	}
	return a.repo.ListUserRoles(ctx, target, time.Now())
}

func (a *Auth) AssignRole(ctx context.Context, actor, target, role uuid.UUID, level domain.RoleLevel, validUntil *time.Time, tags []string) error {
	now := time.Now()
	if validUntil != nil && !validUntil.After(now) {
		return ErrInvalidArgument
	}
	ok, err := a.CanAssignRole(ctx, actor, role)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return a.repo.AssignUserRoleWithTagGrants(ctx, target, role, level, &actor, now, validUntil, tags)
}

func (a *Auth) ChangeMembershipTag(ctx context.Context, actor, target, role uuid.UUID, tag string, add bool) error {
	ok, err := a.CanAssignRole(ctx, actor, role)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	if add {
		r, loadErr := a.repo.GetRoleByID(ctx, role)
		if loadErr != nil {
			return loadErr
		}
		if r == nil {
			return ErrNotFound
		}
		configured := false
		for _, candidate := range r.Tags {
			configured = configured || candidate == tag
		}
		if !configured {
			return ErrTagNotConfigured
		}
		return a.repo.AddUserRoleTag(ctx, target, role, tag)
	}
	return a.repo.DeleteUserRoleTag(ctx, target, role, tag)
}

func (a *Auth) RemoveRole(ctx context.Context, actor, target, role uuid.UUID) error {
	ok, err := a.CanAssignRole(ctx, actor, role)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return a.repo.RemoveUserRole(ctx, target, role)
}

func (a *Auth) RequestRole(ctx context.Context, actor, target, role uuid.UUID) (bool, uuid.UUID, error) {
	if target != actor {
		ok, err := a.CanAssignRole(ctx, actor, role)
		if err != nil {
			return false, uuid.Nil, err
		}
		if !ok {
			return false, uuid.Nil, ErrForbidden
		}
	}
	return a.RequestRoleMembership(ctx, actor, target, role)
}

func (a *Auth) PendingRoleRequests(ctx context.Context, actor, role uuid.UUID) ([]repository.RoleRequest, error) {
	ok, err := a.CanAssignRole(ctx, actor, role)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrForbidden
	}
	return a.repo.ListPendingRoleRequests(ctx, role)
}

func (a *Auth) DecideRoleRequest(ctx context.Context, actor, requestID uuid.UUID, approve bool) error {
	request, err := a.repo.GetRoleRequest(ctx, requestID)
	if err != nil {
		return err
	}
	if request == nil {
		return ErrNotFound
	}
	if request.Status != domain.RoleRequestPending {
		return ErrRequestNotPending
	}
	ok, err := a.CanAssignRole(ctx, actor, request.RoleID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	err = a.repo.DecideRoleRequestWithMembership(ctx, requestID, approve, actor, time.Now())
	if errors.Is(err, repository.ErrRoleRequestNotPending) {
		return ErrRequestNotPending
	}
	return err
}
