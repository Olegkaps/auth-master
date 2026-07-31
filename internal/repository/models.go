package repository

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type userModel struct {
	ID                uuid.UUID `gorm:"type:uuid;primaryKey"`
	Login             string    `gorm:"uniqueIndex;not null"`
	Email             *string   `gorm:"uniqueIndex"`
	Kind              string    `gorm:"type:user_kind;not null;default:human"`
	PasswordHash      *string
	ServiceSecretHash *string
	Superuser         bool `gorm:"not null;default:false"`
	PasswordChangedAt *time.Time
	LockedUntil       *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func (userModel) TableName() string { return "users" }

func (u *userModel) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

type roleModel struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey"`
	Name        string    `gorm:"uniqueIndex;not null"`
	Description string    `gorm:"not null;default:''"`
	// ParentID is retained only to migrate deployments that used the original
	// single-parent hierarchy. New hierarchy writes use role_mounts.
	ParentID  *uuid.UUID `gorm:"type:uuid;index"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type roleMountModel struct {
	ChildRoleID  uuid.UUID `gorm:"type:uuid;primaryKey"`
	ParentRoleID uuid.UUID `gorm:"type:uuid;primaryKey;index"`
	CreatedAt    time.Time
}

func (roleMountModel) TableName() string { return "role_mounts" }

func (roleModel) TableName() string { return "roles" }

func (r *roleModel) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

type userRoleModel struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey"`
	UserID     uuid.UUID  `gorm:"type:uuid;not null;uniqueIndex:idx_user_role_pair,priority:1"`
	RoleID     uuid.UUID  `gorm:"type:uuid;not null;uniqueIndex:idx_user_role_pair,priority:2"`
	Level      string     `gorm:"type:role_level;not null;default:member"`
	ValidFrom  time.Time  `gorm:"not null"`
	ValidUntil *time.Time `gorm:""`
	GrantedBy  *uuid.UUID `gorm:"type:uuid"`
	CreatedAt  time.Time
}

func (userRoleModel) TableName() string { return "user_roles" }

func (ur *userRoleModel) BeforeCreate(tx *gorm.DB) error {
	if ur.ID == uuid.Nil {
		ur.ID = uuid.New()
	}
	return nil
}

type signingKeyModel struct {
	Kid          string `gorm:"primaryKey"`
	SecretCipher []byte `gorm:"not null"`
	Nonce        []byte `gorm:"not null"`
	CreatedAt    time.Time
	ValidFrom    time.Time `gorm:"not null"`
	DeprecatedAt *time.Time
	IsCurrent    bool `gorm:"not null;default:false"`
}

func (signingKeyModel) TableName() string { return "signing_keys" }

type refreshSessionModel struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID      uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_refresh_user_dev,priority:1;index"`
	DeviceID    string    `gorm:"not null;uniqueIndex:idx_refresh_user_dev,priority:2"`
	DeviceLabel *string
	TokenHash   []byte `gorm:"not null"`
	CreatedAt   time.Time
	ExpiresAt   time.Time  `gorm:"not null"`
	UsedAt      *time.Time `gorm:""`
	RevokedAt   *time.Time `gorm:""`
}

func (refreshSessionModel) TableName() string { return "refresh_sessions" }

func (r *refreshSessionModel) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

type passwordHistoryModel struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID       uuid.UUID `gorm:"type:uuid;not null;index"`
	PasswordHash string    `gorm:"not null"`
	Ciphertext   []byte    `gorm:"not null"`
	Nonce        []byte    `gorm:"not null"`
	CreatedAt    time.Time
}

func (passwordHistoryModel) TableName() string { return "password_history" }

func (p *passwordHistoryModel) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

type emailOTPModel struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID        uuid.UUID `gorm:"type:uuid;not null"`
	Purpose       string    `gorm:"type:otp_purpose;not null"`
	CodeHash      []byte    `gorm:"not null"`
	ExpiresAt     time.Time `gorm:"not null"`
	ConsumedAt    *time.Time
	AttemptCount  int     `gorm:"not null;default:0"`
	CorrelationID *string `gorm:"index"`
	CreatedAt     time.Time
}

func (emailOTPModel) TableName() string { return "email_otp_challenges" }

func (e *emailOTPModel) BeforeCreate(tx *gorm.DB) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	return nil
}

type failedLoginModel struct {
	ID        int64 `gorm:"primaryKey;autoIncrement"`
	LoginNorm string
	IP        *string `gorm:"type:inet"`
	CreatedAt time.Time
}

func (failedLoginModel) TableName() string { return "failed_login_attempts" }

type stepUp2FAModel struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey"`
	CorrelationID string    `gorm:"uniqueIndex;not null"`
	UserID        uuid.UUID `gorm:"type:uuid;not null;index:idx_grpc2fa_user_status,priority:1"`
	Status        string    `gorm:"not null;default:pending;index:idx_grpc2fa_user_status,priority:2"`
	ExpiresAt     time.Time `gorm:"not null"`
	ResolvedAt    *time.Time
	CreatedAt     time.Time
}

func (stepUp2FAModel) TableName() string { return "grpc_two_fa_sessions" }

func (g *stepUp2FAModel) BeforeCreate(tx *gorm.DB) error {
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	return nil
}

type roleRequestModel struct {
	ID           uuid.UUID  `gorm:"type:uuid;primaryKey"`
	RequesterID  uuid.UUID  `gorm:"type:uuid;not null"`
	TargetUserID uuid.UUID  `gorm:"type:uuid;not null"`
	RoleID       uuid.UUID  `gorm:"type:uuid;not null"`
	Status       string     `gorm:"type:role_request_status;not null;default:pending"`
	DecidedBy    *uuid.UUID `gorm:"type:uuid"`
	CreatedAt    time.Time
	DecidedAt    *time.Time
}

func (roleRequestModel) TableName() string { return "role_requests" }

func (r *roleRequestModel) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

type registrationInviteModel struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"`
	TokenHash []byte    `gorm:"uniqueIndex;not null"`
	Email     *string   `gorm:""`
	Superuser bool      `gorm:"not null;default:false"`
	ExpiresAt time.Time `gorm:"not null"`
	UsedAt    *time.Time
	CreatedBy uuid.UUID `gorm:"type:uuid;not null"`
	CreatedAt time.Time
}

func (registrationInviteModel) TableName() string { return "registration_invites" }

func (m *registrationInviteModel) BeforeCreate(tx *gorm.DB) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	return nil
}

// magicLinkModel is a single-use, time-limited passwordless login link.
type magicLinkModel struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"`
	TokenHash []byte    `gorm:"uniqueIndex;not null"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index"`
	ExpiresAt time.Time `gorm:"not null"`
	UsedAt    *time.Time
	CreatedAt time.Time
}

func (magicLinkModel) TableName() string { return "login_magic_links" }

func (m *magicLinkModel) BeforeCreate(tx *gorm.DB) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	return nil
}
