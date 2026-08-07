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
	// RoleDirectMember grants only the selected role; it is not inherited by subroles.
	RoleDirectMember RoleLevel = "direct_member"
	RoleMember       RoleLevel = "member"
	RoleRoleAdmin    RoleLevel = "role_admin"
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
	BannedAt          *time.Time
	BannedBy          *uuid.UUID
	BanReason         string
	CreatedAt         time.Time
}

type Role struct {
	ID          uuid.UUID
	Name        string
	Description string
	// ParentIDs contains every role this role is mounted under. Membership and
	// role-administrator authority are inherited from every ancestor.
	ParentIDs []uuid.UUID
	// ParentID is a compatibility view of the first mount. New code must use
	// ParentIDs because a role can have multiple parents.
	ParentID  *uuid.UUID
	Tags      []string
	CreatedAt time.Time
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
	OTPPasswordReset  OTPPurpose = "password_reset"
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
