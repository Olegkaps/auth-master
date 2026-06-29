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

func (s *Store) CreateRole(ctx context.Context, name, description string) (uuid.UUID, error) {
	r := roleModel{Name: name, Description: description}
	if err := s.db.WithContext(ctx).Create(&r).Error; err != nil {
		return uuid.Nil, err
	}
	return r.ID, nil
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
	return roleToDomain(&m), nil
}

func roleToDomain(m *roleModel) *domain.Role {
	return &domain.Role{ID: m.ID, Name: m.Name, Description: m.Description, CreatedAt: m.CreatedAt}
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
	return list, nil
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
