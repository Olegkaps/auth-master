package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Store) CreateRole(ctx context.Context, name, description string, parentID *uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		r := roleModel{Name: name, Description: description}
		if err := tx.Create(&r).Error; err != nil {
			return err
		}
		id = r.ID
		if parentID != nil {
			return tx.Create(&roleMountModel{ChildRoleID: id, ParentRoleID: *parentID}).Error
		}
		return nil
	})
	return id, err
}

// SetRoleParent sets or clears a role's parent. Callers must first ensure the
// change does not introduce a cycle (see RoleHasAncestor).
func (s *Store) SetRoleParent(ctx context.Context, roleID uuid.UUID, parentID *uuid.UUID) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("child_role_id = ?", roleID).Delete(&roleMountModel{}).Error; err != nil {
			return err
		}
		if parentID == nil {
			return nil
		}
		return tx.Create(&roleMountModel{ChildRoleID: roleID, ParentRoleID: *parentID}).Error
	})
}

func (s *Store) MountRole(ctx context.Context, roleID, parentID uuid.UUID) error {
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).
		Create(&roleMountModel{ChildRoleID: roleID, ParentRoleID: parentID}).Error
}

func (s *Store) UnmountRole(ctx context.Context, roleID, parentID uuid.UUID) error {
	return s.db.WithContext(ctx).Where("child_role_id = ? AND parent_role_id = ?", roleID, parentID).
		Delete(&roleMountModel{}).Error
}

// RoleAncestors returns roleID followed by each ancestor up the parent chain
// (self-inclusive). A depth guard bounds any accidental cycle.
func (s *Store) RoleAncestors(ctx context.Context, roleID uuid.UUID) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := s.db.WithContext(ctx).Raw(`
		WITH RECURSIVE anc(id, depth, path) AS (
			SELECT id, 0, ARRAY[id] FROM roles WHERE id = ?
			UNION ALL
			SELECT rm.parent_role_id, anc.depth + 1, anc.path || rm.parent_role_id
			FROM role_mounts rm JOIN anc ON rm.child_role_id = anc.id
			WHERE anc.depth < 64 AND NOT rm.parent_role_id = ANY(anc.path)
		)
		SELECT DISTINCT id FROM anc`, roleID).Scan(&ids).Error
	return ids, err
}

// RoleHasAncestor reports whether candidate is roleID itself or an ancestor of
// roleID — used to reject parent assignments that would create a cycle.
func (s *Store) RoleHasAncestor(ctx context.Context, roleID, candidate uuid.UUID) (bool, error) {
	anc, err := s.RoleAncestors(ctx, roleID)
	if err != nil {
		return false, err
	}
	for _, id := range anc {
		if id == candidate {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) GetRoleByName(ctx context.Context, name string) (*domain.Role, error) {
	var m roleModel
	err := s.db.WithContext(ctx).Where("name = ?", name).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return roleToDomain(&m), nil
}

func (s *Store) GetRoleByID(ctx context.Context, id uuid.UUID) (*domain.Role, error) {
	var m roleModel
	err := s.db.WithContext(ctx).Where("id = ?", id).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	role := roleToDomain(&m)
	roles := []domain.Role{*role}
	if err := s.loadRoleParents(ctx, roles); err != nil {
		return nil, err
	}
	return &roles[0], nil
}

func roleToDomain(m *roleModel) *domain.Role {
	return &domain.Role{ID: m.ID, Name: m.Name, Description: m.Description, CreatedAt: m.CreatedAt}
}

func (s *Store) loadRoleParents(ctx context.Context, roles []domain.Role) error {
	var mounts []roleMountModel
	if err := s.db.WithContext(ctx).Order("parent_role_id").Find(&mounts).Error; err != nil {
		return err
	}
	byChild := make(map[uuid.UUID][]uuid.UUID)
	for _, mount := range mounts {
		byChild[mount.ChildRoleID] = append(byChild[mount.ChildRoleID], mount.ParentRoleID)
	}
	for i := range roles {
		roles[i].ParentIDs = byChild[roles[i].ID]
		if len(roles[i].ParentIDs) > 0 {
			first := roles[i].ParentIDs[0]
			roles[i].ParentID = &first
		}
	}
	return nil
}

func (s *Store) ListRoles(ctx context.Context) ([]domain.Role, error) {
	var rows []roleModel
	if err := s.db.WithContext(ctx).Order("name").Find(&rows).Error; err != nil {
		return nil, err
	}
	list := make([]domain.Role, 0, len(rows))
	for i := range rows {
		list = append(list, *roleToDomain(&rows[i]))
	}
	return list, s.loadRoleParents(ctx, list)
}

// DeleteRole removes a role, its hierarchy edges, memberships, and requests.
func (s *Store) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var role roleModel
		if err := tx.Where("id = ?", roleID).Take(&role).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		// Preserve reachability by mounting each direct child under every direct
		// parent of the deleted role before removing its edges.
		if err := tx.Exec(`
			INSERT INTO role_mounts (child_role_id, parent_role_id, created_at)
			SELECT children.child_role_id, parents.parent_role_id, NOW()
			FROM role_mounts children CROSS JOIN role_mounts parents
			WHERE children.parent_role_id = ? AND parents.child_role_id = ?
			ON CONFLICT (child_role_id, parent_role_id) DO NOTHING`, roleID, roleID).Error; err != nil {
			return err
		}
		if err := tx.Where("child_role_id = ? OR parent_role_id = ?", roleID, roleID).Delete(&roleMountModel{}).Error; err != nil {
			return err
		}
		if err := tx.Where("role_id = ?", roleID).Delete(&userRoleModel{}).Error; err != nil {
			return err
		}
		if err := tx.Where("role_id = ?", roleID).Delete(&roleRequestModel{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", roleID).Delete(&roleModel{}).Error
	})
}

// RoleMember is one active membership of a role, enriched with user identity.
type RoleMember struct {
	UserID     uuid.UUID
	Login      string
	Email      *string
	Level      domain.RoleLevel
	ValidUntil *time.Time
}

// ListRoleMembers returns active members of a role (admins first), with login/email.
func (s *Store) ListRoleMembers(ctx context.Context, roleID uuid.UUID, at time.Time) ([]RoleMember, error) {
	var rows []struct {
		UserID     uuid.UUID
		Login      string
		Email      *string
		Level      string
		ValidUntil *time.Time
	}
	err := s.db.WithContext(ctx).
		Table("user_roles as ur").
		Select("ur.user_id, u.login, u.email, ur.level, ur.valid_until").
		Joins("JOIN users u ON u.id = ur.user_id").
		Where("ur.role_id = ? AND ur.valid_from <= ? AND (ur.valid_until IS NULL OR ur.valid_until > ?)", roleID, at, at).
		Order("ur.level DESC, u.login ASC").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]RoleMember, 0, len(rows))
	for _, r := range rows {
		out = append(out, RoleMember{UserID: r.UserID, Login: r.Login, Email: r.Email, Level: domain.RoleLevel(r.Level), ValidUntil: r.ValidUntil})
	}
	return out, nil
}

func (s *Store) UpdateRoleDescription(ctx context.Context, id uuid.UUID, description string) error {
	return s.db.WithContext(ctx).Model(&roleModel{}).Where("id = ?", id).Updates(map[string]any{
		"description": description,
	}).Error
}

func (s *Store) AssignUserRole(ctx context.Context, userID, roleID uuid.UUID, level domain.RoleLevel, grantedBy *uuid.UUID, validFrom time.Time, validUntil *time.Time) error {
	ur := userRoleModel{
		UserID:     userID,
		RoleID:     roleID,
		Level:      string(level),
		GrantedBy:  grantedBy,
		ValidFrom:  validFrom,
		ValidUntil: validUntil,
	}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "role_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"level", "valid_from", "valid_until", "granted_by"}),
	}).Create(&ur).Error
}

func (s *Store) RemoveUserRole(ctx context.Context, userID, roleID uuid.UUID) error {
	return s.db.WithContext(ctx).Where("user_id = ? AND role_id = ?", userID, roleID).Delete(&userRoleModel{}).Error
}

func (s *Store) ListUserRoles(ctx context.Context, userID uuid.UUID, at time.Time) ([]domain.UserRole, error) {
	var rows []userRoleModel
	err := s.db.WithContext(ctx).
		Where("user_id = ? AND valid_from <= ? AND (valid_until IS NULL OR valid_until > ?)", userID, at, at).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	list := make([]domain.UserRole, 0, len(rows))
	for _, ur := range rows {
		list = append(list, domain.UserRole{
			ID:         ur.ID,
			UserID:     ur.UserID,
			RoleID:     ur.RoleID,
			Level:      domain.RoleLevel(ur.Level),
			ValidFrom:  ur.ValidFrom,
			ValidUntil: ur.ValidUntil,
			GrantedBy:  ur.GrantedBy,
		})
	}
	return list, nil
}

func (s *Store) GetUserRoleLevel(ctx context.Context, userID, roleID uuid.UUID, at time.Time) (domain.RoleLevel, bool, error) {
	var ur userRoleModel
	err := s.db.WithContext(ctx).
		Select("level").
		Where("user_id = ? AND role_id = ? AND valid_from <= ? AND (valid_until IS NULL OR valid_until > ?)",
			userID, roleID, at, at).
		Take(&ur).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return domain.RoleLevel(ur.Level), true, nil
}

func (s *Store) UserHasRoleName(ctx context.Context, userID uuid.UUID, roleName string, at time.Time) (bool, error) {
	var ur userRoleModel
	err := s.db.WithContext(ctx).
		Model(&userRoleModel{}).
		Joins("JOIN roles r ON r.id = user_roles.role_id").
		Where("user_roles.user_id = ? AND r.name = ? AND user_roles.valid_from <= ? AND (user_roles.valid_until IS NULL OR user_roles.valid_until > ?)",
			userID, roleName, at, at).
		Limit(1).
		Take(&ur).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
