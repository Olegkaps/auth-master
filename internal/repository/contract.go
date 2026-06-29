package repository

import (
	"context"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
)

// Repository is the persistence surface used by the service and HTTP layer.
// Mock it in tests (e.g. github.com/stretchr/testify/mock).
type Repository interface {
	Ping(ctx context.Context) error

	CreateHumanUser(ctx context.Context, login, email, passwordHash string) (uuid.UUID, error)
	CreateServiceUser(ctx context.Context, login, secretHash string) (uuid.UUID, error)
	GetUserByLogin(ctx context.Context, login string) (*domain.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	SetLockedUntil(ctx context.Context, userID uuid.UUID, t *time.Time) error
	UpdatePassword(ctx context.Context, userID uuid.UUID, hash string) error
	ListPasswordHistory(ctx context.Context, userID uuid.UUID, limit int) ([]PasswordHistoryEntry, error)
	InsertPasswordHistory(ctx context.Context, userID uuid.UUID, hash string, ciphertext, nonce []byte) error
	TrimPasswordHistory(ctx context.Context, userID uuid.UUID, keep int) error
	ListUsers(ctx context.Context, limit int) ([]domain.User, error)
	CountHumanUsers(ctx context.Context) (int64, error)
	SetSuperuser(ctx context.Context, userID uuid.UUID, v bool) error

	CountActiveRefreshSessions(ctx context.Context, userID uuid.UUID) (int64, error)
	DeleteOldestRefreshSession(ctx context.Context, userID uuid.UUID) error
	UpsertRefreshSession(ctx context.Context, userID uuid.UUID, deviceID, deviceLabel string, tokenHash []byte, expiresAt time.Time) (uuid.UUID, error)
	ReplaceRefreshToken(ctx context.Context, id uuid.UUID, oldHash, newHash []byte, expiresAt time.Time) error
	GetRefreshByUserDevice(ctx context.Context, userID uuid.UUID, deviceID string) (*RefreshRow, error)
	GetRefreshByID(ctx context.Context, id uuid.UUID) (*RefreshRow, error)
	ListRefreshSessions(ctx context.Context, userID uuid.UUID) ([]domain.RefreshSession, error)
	MarkRefreshUsed(ctx context.Context, id uuid.UUID) error
	RevokeRefreshSession(ctx context.Context, id uuid.UUID) error
	RevokeRefreshByHash(ctx context.Context, userID uuid.UUID, tokenHash []byte) error
	FindRefreshByTokenHash(ctx context.Context, tokenHash []byte) (*RefreshRow, error)

	CreateRole(ctx context.Context, name, description string) (uuid.UUID, error)
	GetRoleByName(ctx context.Context, name string) (*domain.Role, error)
	GetRoleByID(ctx context.Context, id uuid.UUID) (*domain.Role, error)
	ListRoles(ctx context.Context) ([]domain.Role, error)
	UpdateRoleDescription(ctx context.Context, id uuid.UUID, description string) error
	AssignUserRole(ctx context.Context, userID, roleID uuid.UUID, level domain.RoleLevel, grantedBy *uuid.UUID, validFrom time.Time, validUntil *time.Time) error
	RemoveUserRole(ctx context.Context, userID, roleID uuid.UUID) error
	ListUserRoles(ctx context.Context, userID uuid.UUID, at time.Time) ([]domain.UserRole, error)
	GetUserRoleLevel(ctx context.Context, userID, roleID uuid.UUID, at time.Time) (domain.RoleLevel, bool, error)
	UserHasRoleName(ctx context.Context, userID uuid.UUID, roleName string, at time.Time) (bool, error)

	GetSigningKeyMaterial(ctx context.Context, kid string) (*SigningKeyMaterial, error)
	GetCurrentSigningKeyMaterial(ctx context.Context) (*SigningKeyMaterial, error)
	InsertSigningKey(ctx context.Context, kid string, cipher, nonce []byte, deprecateOthers bool) error
	DeprecateCurrentAndSet(ctx context.Context, newKid string, newCipher, newNonce []byte) error
	CountSigningKeys(ctx context.Context) (int64, error)

	CreateEmailOTP(ctx context.Context, userID uuid.UUID, purpose domain.OTPPurpose, codeHash []byte, expiresAt time.Time, correlation *string) (uuid.UUID, error)
	GetLatestOTP(ctx context.Context, userID uuid.UUID, purpose domain.OTPPurpose) (*OTPRow, error)
	GetOTPByCorrelation(ctx context.Context, correlation string) (*OTPRow, error)
	ConsumeOTP(ctx context.Context, id uuid.UUID) error
	IncrementOTPAttempt(ctx context.Context, id uuid.UUID) error

	CountFailedLogins(ctx context.Context, loginNorm string, since time.Time) (int64, error)
	InsertFailedLogin(ctx context.Context, loginNorm string, ip net.IP) error
	DeleteOldFailedLogins(ctx context.Context, before time.Time) error

	CreateStepUp2FASession(ctx context.Context, correlationID string, userID uuid.UUID, expiresAt time.Time) error
	GetStepUp2FA(ctx context.Context, correlationID string) (*StepUp2FASession, error)
	ApproveStepUp2FA(ctx context.Context, correlationID string) error
	ExpireStepUp2FA(ctx context.Context, correlationID string) error
	MarkExpiredStepUp2FAByTime(ctx context.Context, now time.Time) error

	CreateRoleRequest(ctx context.Context, requesterID, targetUserID, roleID uuid.UUID) (uuid.UUID, error)
	ListPendingRoleRequests(ctx context.Context, roleID uuid.UUID) ([]RoleRequest, error)
	DecideRoleRequest(ctx context.Context, id uuid.UUID, approved bool, decidedBy uuid.UUID) error
	GetRoleRequest(ctx context.Context, id uuid.UUID) (*RoleRequest, error)

	InsertRegistrationInvite(ctx context.Context, tokenHash []byte, email *string, expiresAt time.Time, createdBy uuid.UUID) (uuid.UUID, error)
	GetValidRegistrationInviteByTokenHash(ctx context.Context, tokenHash []byte) (*RegistrationInvite, error)
	MarkRegistrationInviteUsed(ctx context.Context, id uuid.UUID) error
}

var _ Repository = (*Store)(nil)
