package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Store) CreateRole(ctx context.Context, name, description string, parentID *uuid.UUID) (uuid.UUID, error) {
	parents := []uuid.UUID(nil)
	if parentID != nil {
		parents = append(parents, *parentID)
	}
	return s.CreateRoleWithParents(ctx, name, description, parents)
}

func (s *Store) CreateRoleWithParents(ctx context.Context, name, description string, parentIDs []uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	name = strings.TrimSpace(name)
	if name == "" {
		return uuid.Nil, errors.New("role name is required")
	}
	parents := make([]uuid.UUID, 0, len(parentIDs))
	seen := make(map[uuid.UUID]struct{}, len(parentIDs))
	for _, parentID := range parentIDs {
		if parentID == uuid.Nil {
			return uuid.Nil, errors.New("parent role is required")
		}
		if _, exists := seen[parentID]; exists {
			continue
		}
		seen[parentID] = struct{}{}
		parents = append(parents, parentID)
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockRoleHierarchy(tx); err != nil {
			return err
		}
		if len(parents) > 0 {
			var count int64
			if err := tx.Model(&roleModel{}).Where("id IN ?", parents).Count(&count).Error; err != nil {
				return err
			}
			if count != int64(len(parents)) {
				return errors.New("parent role not found")
			}
		}
		r := roleModel{Name: name, Description: description}
		if err := tx.Create(&r).Error; err != nil {
			return err
		}
		id = r.ID
		for _, parentID := range parents {
			if err := tx.Create(&roleMountModel{ChildRoleID: id, ParentRoleID: parentID}).Error; err != nil {
				return err
			}
		}
		return nil
	})
	return id, err
}

// SetRoleParent sets or clears a role's parent. Callers must first ensure the
// change does not introduce a cycle (see RoleHasAncestor).
func (s *Store) SetRoleParent(ctx context.Context, roleID uuid.UUID, parentID *uuid.UUID) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockRoleHierarchy(tx); err != nil {
			return err
		}
		if err := requireRole(tx, roleID); err != nil {
			return err
		}
		if parentID != nil {
			if err := requireRole(tx, *parentID); err != nil {
				return fmt.Errorf("parent: %w", err)
			}
			cycle, err := roleHasAncestorTx(tx, *parentID, roleID)
			if err != nil {
				return err
			}
			if cycle {
				return errors.New("parent would create a cycle")
			}
		}
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
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockRoleHierarchy(tx); err != nil {
			return err
		}
		if err := requireRole(tx, roleID); err != nil {
			return err
		}
		if err := requireRole(tx, parentID); err != nil {
			return fmt.Errorf("parent: %w", err)
		}
		cycle, err := roleHasAncestorTx(tx, parentID, roleID)
		if err != nil {
			return err
		}
		if cycle {
			return errors.New("mount would create a cycle")
		}
		return tx.Clauses(clause.OnConflict{DoNothing: true}).
			Create(&roleMountModel{ChildRoleID: roleID, ParentRoleID: parentID}).Error
	})
}

func (s *Store) UnmountRole(ctx context.Context, roleID, parentID uuid.UUID) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockRoleHierarchy(tx); err != nil {
			return err
		}
		return tx.Where("child_role_id = ? AND parent_role_id = ?", roleID, parentID).
			Delete(&roleMountModel{}).Error
	})
}

func lockRoleHierarchy(tx *gorm.DB) error {
	return tx.Exec("SELECT pg_advisory_xact_lock(hashtext('auth-master-role-hierarchy'))").Error
}

func requireRole(tx *gorm.DB, roleID uuid.UUID) error {
	var count int64
	if err := tx.Model(&roleModel{}).Where("id = ?", roleID).Count(&count).Error; err != nil {
		return err
	}
	if count != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func roleHasAncestorTx(tx *gorm.DB, roleID, candidate uuid.UUID) (bool, error) {
	var found bool
	err := tx.Raw(`WITH RECURSIVE anc(id, depth, path) AS (
		SELECT id, 0, ARRAY[id] FROM roles WHERE id = ?
		UNION ALL
		SELECT rm.parent_role_id, anc.depth + 1, anc.path || rm.parent_role_id
		FROM role_mounts rm JOIN anc ON rm.child_role_id = anc.id
		WHERE anc.depth < 64 AND NOT rm.parent_role_id = ANY(anc.path)
	) SELECT EXISTS(SELECT 1 FROM anc WHERE id = ?)`, roleID, candidate).Scan(&found).Error
	return found, err
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
	return roleHasAncestorTx(s.db.WithContext(ctx), roleID, candidate)
}

func (s *Store) GetRoleByName(ctx context.Context, name string) (*domain.Role, error) {
	var m roleModel
	err := s.db.WithContext(ctx).Where("LOWER(name) = ?", strings.ToLower(strings.TrimSpace(name))).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	role := roleToDomain(&m)
	roles := []domain.Role{*role}
	if err := s.loadRoleDetails(ctx, roles); err != nil {
		return nil, err
	}
	return &roles[0], nil
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
	if err := s.loadRoleDetails(ctx, roles); err != nil {
		return nil, err
	}
	return &roles[0], nil
}

func roleToDomain(m *roleModel) *domain.Role {
	return &domain.Role{ID: m.ID, Name: m.Name, Description: m.Description, CreatedAt: m.CreatedAt}
}

func (s *Store) loadRoleParents(ctx context.Context, roles []domain.Role) error {
	if len(roles) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, len(roles))
	for i := range roles {
		ids[i] = roles[i].ID
	}
	var mounts []roleMountModel
	if err := s.db.WithContext(ctx).Where("child_role_id IN ?", ids).Order("parent_role_id").Find(&mounts).Error; err != nil {
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

func (s *Store) loadRoleDetails(ctx context.Context, roles []domain.Role) error {
	if err := s.loadRoleParents(ctx, roles); err != nil {
		return err
	}
	if len(roles) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, len(roles))
	for i := range roles {
		ids[i] = roles[i].ID
	}
	var rows []roleTagModel
	if err := s.db.WithContext(ctx).Where("role_id IN ?", ids).Order("tag").Find(&rows).Error; err != nil {
		return err
	}
	byRole := map[uuid.UUID][]string{}
	for _, row := range rows {
		byRole[row.RoleID] = append(byRole[row.RoleID], row.Tag)
	}
	for i := range roles {
		roles[i].Tags = byRole[roles[i].ID]
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
	return list, s.loadRoleDetails(ctx, list)
}

func (s *Store) SearchRoles(ctx context.Context, query string, after *PageCursor, limit int, countTotal bool) ([]domain.Role, *PageCursor, *int64, error) {
	db := s.db.WithContext(ctx).Model(&roleModel{})
	if q := strings.TrimSpace(query); q != "" {
		db = db.Where("LOWER(name) LIKE ?", "%"+strings.ToLower(q)+"%")
	}
	var total *int64
	if countTotal {
		var n int64
		if err := db.Count(&n).Error; err != nil {
			return nil, nil, nil, err
		}
		total = &n
	}
	if after != nil {
		db = db.Where("(LOWER(name), id) > (?, ?)", after.Sort, after.ID)
	}
	var rows []roleModel
	if err := db.Order("LOWER(name) ASC, id ASC").Limit(limit + 1).Find(&rows).Error; err != nil {
		return nil, nil, nil, err
	}
	var next *PageCursor
	if len(rows) > limit {
		last := rows[limit-1]
		next = &PageCursor{Sort: strings.ToLower(last.Name), ID: last.ID}
		rows = rows[:limit]
	}
	out := make([]domain.Role, 0, len(rows))
	for i := range rows {
		out = append(out, *roleToDomain(&rows[i]))
	}
	return out, next, total, s.loadRoleDetails(ctx, out)
}

func (s *Store) ListSubroles(ctx context.Context, roleID uuid.UUID, recursive bool) ([]domain.Role, error) {
	var rows []roleModel
	if recursive {
		err := s.db.WithContext(ctx).Raw(`WITH RECURSIVE sub(id, depth, path) AS (
		SELECT child_role_id, 1, ARRAY[?::uuid, child_role_id] FROM role_mounts WHERE parent_role_id = ?
		UNION ALL SELECT rm.child_role_id, sub.depth + 1, sub.path || rm.child_role_id FROM role_mounts rm JOIN sub ON rm.parent_role_id = sub.id
		WHERE sub.depth < 64 AND NOT rm.child_role_id = ANY(sub.path)) SELECT DISTINCT r.* FROM roles r JOIN sub ON sub.id = r.id ORDER BY r.name`, roleID, roleID).Scan(&rows).Error
		if err != nil {
			return nil, err
		}
	} else if err := s.db.WithContext(ctx).Joins("JOIN role_mounts rm ON rm.child_role_id = roles.id").Where("rm.parent_role_id = ?", roleID).Order("roles.name").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.Role, 0, len(rows))
	for i := range rows {
		out = append(out, *roleToDomain(&rows[i]))
	}
	return out, s.loadRoleDetails(ctx, out)
}

func (s *Store) AddRoleTag(ctx context.Context, roleID uuid.UUID, tag string) error {
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&roleTagModel{RoleID: roleID, Tag: tag}).Error
}

func (s *Store) DeleteRoleTag(ctx context.Context, roleID uuid.UUID, tag string) error {
	return s.db.WithContext(ctx).Where("role_id = ? AND tag = ?", roleID, tag).Delete(&roleTagModel{}).Error
}

func (s *Store) RenameRoleTag(ctx context.Context, roleID uuid.UUID, oldTag, newTag string) error {
	if oldTag == newTag {
		return nil
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&roleTagModel{}).Where("role_id = ? AND tag = ?", roleID, oldTag).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			return gorm.ErrRecordNotFound
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&roleTagModel{RoleID: roleID, Tag: newTag}).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO user_role_tags (user_role_id, tag)
			SELECT urt.user_role_id, ? FROM user_role_tags urt JOIN user_roles ur ON ur.id=urt.user_role_id
			WHERE ur.role_id=? AND urt.tag=? ON CONFLICT (user_role_id, tag) DO NOTHING`, newTag, roleID, oldTag).Error; err != nil {
			return err
		}
		if err := tx.Exec(`DELETE FROM user_role_tags urt USING user_roles ur WHERE urt.user_role_id=ur.id AND ur.role_id=? AND urt.tag=?`, roleID, oldTag).Error; err != nil {
			return err
		}
		return tx.Where("role_id = ? AND tag = ?", roleID, oldTag).Delete(&roleTagModel{}).Error
	})
}

// DeleteRole removes a role, its hierarchy edges, memberships, and requests.
func (s *Store) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockRoleHierarchy(tx); err != nil {
			return err
		}
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
		if err := tx.Exec(`DELETE FROM user_role_tags urt USING user_roles ur WHERE urt.user_role_id=ur.id AND ur.role_id=?`, roleID).Error; err != nil {
			return err
		}
		if err := tx.Where("role_id = ?", roleID).Delete(&userRoleModel{}).Error; err != nil {
			return err
		}
		if err := tx.Where("role_id = ?", roleID).Delete(&roleRequestModel{}).Error; err != nil {
			return err
		}
		if err := tx.Where("role_id = ?", roleID).Delete(&roleTagModel{}).Error; err != nil {
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
	Tags       []string
}

// ListRoleMembers returns active members of a role (admins first), with login/email.
func (s *Store) ListRoleMembers(ctx context.Context, roleID uuid.UUID, at time.Time) ([]RoleMember, error) {
	var rows []struct {
		UserID     uuid.UUID
		Login      string
		Email      *string
		Level      string
		ValidUntil *time.Time
		TagsJSON   string
	}
	err := s.db.WithContext(ctx).
		Table("user_roles as ur").
		Select("ur.user_id, u.login, u.email, ur.level, ur.valid_until, COALESCE(json_agg(urt.tag ORDER BY urt.tag) FILTER (WHERE urt.tag IS NOT NULL), '[]')::text AS tags_json").
		Joins("JOIN users u ON u.id = ur.user_id").
		Joins("LEFT JOIN user_role_tags urt ON urt.user_role_id = ur.id").
		Where("ur.role_id = ? AND ur.valid_from <= ? AND (ur.valid_until IS NULL OR ur.valid_until > ?)", roleID, at, at).
		Group("ur.id, u.id").
		Order("ur.level DESC, u.login ASC").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]RoleMember, 0, len(rows))
	for _, r := range rows {
		var tags []string
		if err := json.Unmarshal([]byte(r.TagsJSON), &tags); err != nil {
			return nil, err
		}
		out = append(out, RoleMember{UserID: r.UserID, Login: r.Login, Email: r.Email, Level: domain.RoleLevel(r.Level), ValidUntil: r.ValidUntil, Tags: tags})
	}
	return out, nil
}

func (s *Store) UpdateRoleDescription(ctx context.Context, id uuid.UUID, description string) error {
	return s.db.WithContext(ctx).Model(&roleModel{}).Where("id = ?", id).Updates(map[string]any{
		"description": description,
	}).Error
}

func (s *Store) AssignUserRole(ctx context.Context, userID, roleID uuid.UUID, level domain.RoleLevel, grantedBy *uuid.UUID, validFrom time.Time, validUntil *time.Time) error {
	return s.assignUserRoleWithTagGrants(ctx, userID, roleID, level, grantedBy, validFrom, validUntil, nil)
}

func (s *Store) AssignUserRoleWithTagGrants(ctx context.Context, userID, roleID uuid.UUID, level domain.RoleLevel, grantedBy *uuid.UUID, validFrom time.Time, validUntil *time.Time, tags []string) error {
	return s.assignUserRoleWithTagGrants(ctx, userID, roleID, level, grantedBy, validFrom, validUntil, tags)
}

func (s *Store) assignUserRoleWithTagGrants(ctx context.Context, userID, roleID uuid.UUID, level domain.RoleLevel, grantedBy *uuid.UUID, validFrom time.Time, validUntil *time.Time, tags []string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return assignUserRoleTx(tx, userID, roleID, level, grantedBy, validFrom, validUntil, tags)
	})
}

func assignUserRoleTx(tx *gorm.DB, userID, roleID uuid.UUID, level domain.RoleLevel, grantedBy *uuid.UUID, validFrom time.Time, validUntil *time.Time, tags []string) error {
	var userCount int64
	if err := tx.Model(&userModel{}).Where("id = ?", userID).Count(&userCount).Error; err != nil {
		return err
	}
	if userCount != 1 {
		return errors.New("user not found")
	}
	if err := requireRole(tx, roleID); err != nil {
		return errors.New("role not found")
	}
	ur := userRoleModel{
		UserID:     userID,
		RoleID:     roleID,
		Level:      string(level),
		GrantedBy:  grantedBy,
		ValidFrom:  validFrom,
		ValidUntil: validUntil,
	}
	if err := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "role_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"level", "valid_from", "valid_until", "granted_by"}),
	}).Create(&ur).Error; err != nil {
		return err
	}
	if len(tags) == 0 {
		return nil
	}
	// On an upsert conflict GORM keeps the generated ID on ur; load the actual
	// membership row before attaching tag pairs.
	if err := tx.Select("id").Where("user_id = ? AND role_id = ?", userID, roleID).Take(&ur).Error; err != nil {
		return err
	}
	var configured int64
	if err := tx.Model(&roleTagModel{}).Where("role_id = ? AND tag IN ?", roleID, tags).Count(&configured).Error; err != nil {
		return err
	}
	if configured != int64(len(tags)) {
		return errors.New("one or more tags are not configured for role")
	}
	for _, tag := range tags {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&userRoleTagModel{UserRoleID: ur.ID, Tag: tag}).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) AddUserRoleTag(ctx context.Context, userID, roleID uuid.UUID, tag string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var membership userRoleModel
		if err := tx.Select("id").Where("user_id = ? AND role_id = ?", userID, roleID).Take(&membership).Error; err != nil {
			return err
		}
		return tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&userRoleTagModel{UserRoleID: membership.ID, Tag: tag}).Error
	})
}

func (s *Store) DeleteUserRoleTag(ctx context.Context, userID, roleID uuid.UUID, tag string) error {
	return s.db.WithContext(ctx).Exec(`DELETE FROM user_role_tags urt USING user_roles ur
		WHERE urt.user_role_id=ur.id AND ur.user_id=? AND ur.role_id=? AND urt.tag=?`, userID, roleID, tag).Error
}

func (s *Store) RemoveUserRole(ctx context.Context, userID, roleID uuid.UUID) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var membership userRoleModel
		err := tx.Select("id").Where("user_id = ? AND role_id = ?", userID, roleID).Take(&membership).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := tx.Where("user_role_id = ?", membership.ID).Delete(&userRoleTagModel{}).Error; err != nil {
			return err
		}
		return tx.Delete(&membership).Error
	})
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

// UserHasEffectiveRole uses one bounded recursive query. Direct membership is
// valid only on the requested role; member and role_admin inherit to subroles.
func (s *Store) UserHasEffectiveRole(ctx context.Context, userID, roleID uuid.UUID, at time.Time) (bool, error) {
	var found bool
	err := s.db.WithContext(ctx).Raw(`WITH RECURSIVE anc(id, depth, path) AS (
		SELECT id, 0, ARRAY[id] FROM roles WHERE id = ? UNION ALL
		SELECT rm.parent_role_id, anc.depth+1, anc.path||rm.parent_role_id FROM role_mounts rm JOIN anc ON rm.child_role_id=anc.id
		WHERE anc.depth < 64 AND NOT rm.parent_role_id=ANY(anc.path))
		SELECT EXISTS(SELECT 1 FROM anc JOIN user_roles ur ON ur.role_id=anc.id
		WHERE ur.user_id=? AND ur.valid_from<=? AND (ur.valid_until IS NULL OR ur.valid_until>?)
		AND (anc.depth=0 OR ur.level IN ('member','role_admin')))`, roleID, userID, at, at).Scan(&found).Error
	return found, err
}

func (s *Store) UserIsEffectiveRoleAdmin(ctx context.Context, userID, roleID uuid.UUID, at time.Time) (bool, error) {
	var found bool
	err := s.db.WithContext(ctx).Raw(`WITH RECURSIVE anc(id, depth, path) AS (
		SELECT id, 0, ARRAY[id] FROM roles WHERE id = ? UNION ALL
		SELECT rm.parent_role_id, anc.depth+1, anc.path||rm.parent_role_id FROM role_mounts rm JOIN anc ON rm.child_role_id=anc.id
		WHERE anc.depth < 64 AND NOT rm.parent_role_id=ANY(anc.path))
		SELECT EXISTS(SELECT 1 FROM anc JOIN user_roles ur ON ur.role_id=anc.id
		WHERE ur.user_id=? AND ur.level='role_admin' AND ur.valid_from<=? AND (ur.valid_until IS NULL OR ur.valid_until>?))`, roleID, userID, at, at).Scan(&found).Error
	return found, err
}

func (s *Store) UserHasEffectiveRoleTag(ctx context.Context, userID, roleID uuid.UUID, tag string, at time.Time) (bool, error) {
	var found bool
	err := s.db.WithContext(ctx).Raw(`WITH RECURSIVE anc(id, depth, path) AS (
		SELECT id, 0, ARRAY[id] FROM roles WHERE id = ? UNION ALL
		SELECT rm.parent_role_id, anc.depth+1, anc.path||rm.parent_role_id FROM role_mounts rm JOIN anc ON rm.child_role_id=anc.id
		WHERE anc.depth < 64 AND NOT rm.parent_role_id=ANY(anc.path))
		SELECT EXISTS(SELECT 1 FROM anc JOIN user_roles ur ON ur.role_id=anc.id
		JOIN user_role_tags urt ON urt.user_role_id=ur.id
		JOIN role_tags rt ON rt.role_id=ur.role_id AND rt.tag=urt.tag
		WHERE ur.user_id=? AND urt.tag=? AND ur.valid_from<=? AND (ur.valid_until IS NULL OR ur.valid_until>?)
		AND (anc.depth=0 OR ur.level IN ('member','role_admin')))`, roleID, userID, strings.ToLower(tag), at, at).Scan(&found).Error
	return found, err
}

type EffectiveRoleAccess struct {
	RoleID    uuid.UUID
	CanManage bool
}

// ListEffectiveRoleAccess is the server-authoritative view used by the SPA.
// direct_member stays local while member and role_admin flow to descendants.
func (s *Store) ListEffectiveRoleAccess(ctx context.Context, userID uuid.UUID, at time.Time) ([]EffectiveRoleAccess, error) {
	var rows []EffectiveRoleAccess
	err := s.db.WithContext(ctx).Raw(`WITH RECURSIVE access(role_id, can_manage, inherits, depth, path) AS (
		SELECT role_id, level = 'role_admin', level IN ('member', 'role_admin'), 0, ARRAY[role_id]
		FROM user_roles WHERE user_id = ? AND valid_from <= ? AND (valid_until IS NULL OR valid_until > ?)
		UNION ALL
		SELECT rm.child_role_id, access.can_manage, access.inherits, access.depth + 1, access.path || rm.child_role_id
		FROM role_mounts rm JOIN access ON rm.parent_role_id = access.role_id
		WHERE access.inherits AND access.depth < 64 AND NOT rm.child_role_id = ANY(access.path)
	)
	SELECT role_id, BOOL_OR(can_manage) AS can_manage FROM access GROUP BY role_id ORDER BY role_id`, userID, at, at).Scan(&rows).Error
	return rows, err
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
