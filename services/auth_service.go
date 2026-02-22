// services/auth_service.go

package services

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/Olegkaps/auth-master/config"
	"github.com/Olegkaps/auth-master/jwt"
	"github.com/Olegkaps/auth-master/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthService struct {
	DB *gorm.DB
}

func NewAuthService(db *gorm.DB) *AuthService {
	return &AuthService{DB: db}
}

func (s *AuthService) Register(email, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := models.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: string(hash),
	}

	return s.DB.Create(&user).Error
}

func (s *AuthService) Login(email, password string, r *http.Request) (string, string, error) {
	var user models.User
	if err := s.DB.Where("email = ?", email).First(&user).Error; err != nil {
		return "", "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", "", err
	}

	accessToken, err := jwt.GenerateAccessToken(user.ID)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := s.generateRefreshToken(user.ID, r)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) generateRefreshToken(userID uuid.UUID, r *http.Request) (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}

	refreshToken := models.RefreshToken{
		TokenID:   uuid.New(),
		UserID:    userID,
		DeviceID:  r.Header.Get("X-Device-ID"),
		Browser:   r.Header.Get("User-Agent"),
		ExpiresAt: time.Now().AddDate(0, 0, config.Cfg.RefreshTokenTTL),
		Used:      false,
	}

	if err := s.DB.Create(&refreshToken).Error; err != nil {
		return "", err
	}

	return hex.EncodeToString(token), nil
}

func (s *AuthService) GenerateTokens(userID uuid.UUID, r *http.Request) (string, string, error) {
	accessToken, err := jwt.GenerateAccessToken(userID)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := s.generateRefreshToken(userID, r)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
