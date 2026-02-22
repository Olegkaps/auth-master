// services/role_service.go

package services

import (
	"time"

	"github.com/Olegkaps/auth-master/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type RoleService struct {
	DB *gorm.DB
}

func NewRoleService(db *gorm.DB) *RoleService {
	return &RoleService{DB: db}
}

func (s *RoleService) CheckRole(subjectID uuid.UUID, role string) (bool, error) {
	var count int64
	err := s.DB.Model(&models.UserRole{}).
		Where("user_id = ? AND role_id IN (SELECT role_id FROM roles WHERE name = ?)", subjectID, role).
		Count(&count).Error

	return count > 0, err
}

func (s *RoleService) AddUserToRole(userID, roleID, issuerID uuid.UUID) error {
	userRole := models.UserRole{
		UserID:     userID,
		RoleID:     roleID,
		AssignedBy: issuerID,
		AssignedAt: time.Now(),
	}

	return s.DB.Create(&userRole).Error
}

func (s *RoleService) ListRoles(subjectID uuid.UUID) ([]string, error) {
	var roles []string
	err := s.DB.Model(&models.Role{}).
		Select("name").
		Joins("JOIN user_roles ON roles.role_id = user_roles.role_id").
		Where("user_roles.user_id = ?", subjectID).
		Find(&roles).Error

	return roles, err
}
