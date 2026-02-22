package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ID           uuid.UUID `gorm:"type:uuid;primaryKey;"`
	Email        string    `gorm:"uniqueIndex"`
	PasswordHash string
	TwoFAEnabled bool
	TwoFASecret  string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type RefreshToken struct {
	gorm.Model
	TokenID   uuid.UUID `gorm:"type:uuid;primaryKey;"`
	UserID    uuid.UUID `gorm:"type:uuid;"`
	DeviceID  string
	Browser   string
	ExpiresAt time.Time
	Used      bool
	CreatedAt time.Time
}

type Role struct {
	gorm.Model
	RoleID      uuid.UUID `gorm:"type:uuid;primaryKey;"`
	Name        string    `gorm:"uniqueIndex"`
	Description string
	IsSystem    bool
	CreatedBy   uuid.UUID `gorm:"type:uuid;"`
	CreatedAt   time.Time
}

type UserRole struct {
	gorm.Model
	UserID     uuid.UUID `gorm:"type:uuid;primaryKey;"`
	RoleID     uuid.UUID `gorm:"type:uuid;primaryKey;"`
	AssignedBy uuid.UUID `gorm:"type:uuid;"`
	AssignedAt time.Time
}

type Service struct {
	gorm.Model
	ServiceID    uuid.UUID `gorm:"type:uuid;primaryKey;"`
	Name         string    `gorm:"uniqueIndex"`
	APIKeyHash   string
	AllowedRoles []uuid.UUID `gorm:"type:uuid[]"`
	CreatedAt    time.Time
}
