// services/token_service.go

package services

import (
	"github.com/Olegkaps/auth-master/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type TokenService struct {
	DB *gorm.DB
}

func NewTokenService(db *gorm.DB) *TokenService {
	return &TokenService{DB: db}
}

func (s *TokenService) InvalidateRefreshToken(tokenID, subjectID uuid.UUID) error {
	return s.DB.Model(&models.RefreshToken{}).
		Where("token_id = ? AND user_id = ?", tokenID, subjectID).
		Update("used", true).Error
}
