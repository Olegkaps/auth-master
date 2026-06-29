package domain

import (
	"time"

	"github.com/google/uuid"
)

type UserKind string

const (
	UserHuman   UserKind = "human"
	UserService UserKind = "service"
)

type RoleLevel string

const (
	RoleMember    RoleLevel = "member"
	RoleRoleAdmin RoleLevel = "role_admin"
)

type User struct {
	ID                uuid.UUID
	Login             string
	Email             *string
	Kind              UserKind
	PasswordHash      *string
	ServiceSecretHash *string
	Superuser         bool
	PasswordChangedAt *time.Time
	LockedUntil       *time.Time
	CreatedAt         time.Time
}

type Role struct {
	ID          uuid.UUID
	Name        string
	Description string
	CreatedAt   time.Time
}

type UserRole struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	RoleID     uuid.UUID
	Level      RoleLevel
	ValidFrom  time.Time
	ValidUntil *time.Time
	GrantedBy  *uuid.UUID
}

type RefreshSession struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	DeviceID    string
	DeviceLabel *string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	UsedAt      *time.Time
	RevokedAt   *time.Time
}

type SigningKey struct {
	Kid          string
	Secret       []byte
	DeprecatedAt *time.Time
	IsCurrent    bool
}

type OTPPurpose string

const (
	OTPLogin          OTPPurpose = "login"
	OTPSessionRevoke  OTPPurpose = "session_revoke"
	OTPPasswordChange OTPPurpose = "password_change"
	// OTPStepUp2FA is email step-up 2FA over REST. DB enum value remains grpc_2fa for existing deployments.
	OTPStepUp2FA OTPPurpose = "grpc_2fa"
	OTPGeneric   OTPPurpose = "generic"
)

type RoleRequestStatus string

const (
	RoleRequestPending  RoleRequestStatus = "pending"
	RoleRequestApproved RoleRequestStatus = "approved"
	RoleRequestRejected RoleRequestStatus = "rejected"
)
