package httptransport

// ErrEnvelope is the standard JSON error body: {"error":"message"}.
type ErrEnvelope struct {
	Error string `json:"error"`
}

// RegisterRequestBody is the body for POST /auth/register.
type RegisterRequestBody struct {
	InviteToken string `json:"invite_token"`
	Login       string `json:"login"`
	Email       string `json:"email"`
	Password    string `json:"password"`
}

// RegisterCreatedResponse is returned on successful registration.
type RegisterCreatedResponse struct {
	UserID string `json:"user_id"`
}

// RegistrationInvitePreviewResponse describes GET /auth/registration-invite.
type RegistrationInvitePreviewResponse struct {
	Valid     bool   `json:"valid"`
	Email     string `json:"email,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// CreateRegistrationInviteRequest is the body for POST /admin/registration-invites.
type CreateRegistrationInviteRequest struct {
	Email      string `json:"email"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// CreateRegistrationInviteResponse is returned when an invite is created.
type CreateRegistrationInviteResponse struct {
	Token           string `json:"token"`
	ExpiresAt       string `json:"expires_at"`
	RegistrationURL string `json:"registration_url"`
}

// LoginRequestBody is the body for POST /auth/login.
type LoginRequestBody struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// LoginOTPResponse is returned when OTP was sent (or would be sent).
type LoginOTPResponse struct {
	OTPSent bool `json:"otp_sent"`
}

// LoginPasswordExpiredResponse is returned with HTTP 403 when the password must be changed.
type LoginPasswordExpiredResponse struct {
	PasswordExpired bool `json:"password_expired"`
}

// LoginVerifyRequestBody is the body for POST /auth/login/verify-otp.
type LoginVerifyRequestBody struct {
	Login       string `json:"login"`
	Code        string `json:"code"`
	DeviceID    string `json:"device_id"`
	DeviceLabel string `json:"device_label"`
}

// TokenPairResponse is returned after OTP verify (includes csrf_token) or refresh (without csrf_token).
type TokenPairResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   string `json:"expires_at"`
	CSRFToken   string `json:"csrf_token,omitempty"`
}

// RefreshRequestBody is the optional JSON body for POST /auth/refresh.
type RefreshRequestBody struct {
	DeviceID    string `json:"device_id"`
	DeviceLabel string `json:"device_label"`
}

// ServiceTokenRequestBody is the body for POST /auth/service-token.
type ServiceTokenRequestBody struct {
	Login  string `json:"login"`
	Secret string `json:"secret"`
}

// TokenIntrospectionResponse is returned by token info / verify-access endpoints.
type TokenIntrospectionResponse struct {
	Subject string `json:"subject"`
	Login   string `json:"login"`
	Kid     string `json:"kid"`
	Typ     string `json:"typ"`
}

// StepUp2FACompleteRequest is the body for POST /auth/step-up-2fa/complete.
type StepUp2FACompleteRequest struct {
	CorrelationID string `json:"correlation_id"`
	Code          string `json:"code"`
}

// StepUp2FAOKResponse is a simple status payload.
type StepUp2FAOKResponse struct {
	Status string `json:"status"`
}

// MeResponse is GET /me.
type MeResponse struct {
	ID        string `json:"id"`
	Login     string `json:"login"`
	Email     any    `json:"email"`
	Kind      string `json:"kind"`
	Superuser bool   `json:"superuser"`
}

// ChangePasswordRequestBody is POST /auth/password.
type ChangePasswordRequestBody struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// SessionsListResponse is GET /sessions.
type SessionsListResponse struct {
	Sessions []SessionRow `json:"sessions"`
}

// SessionRow is one refresh session in the list.
type SessionRow struct {
	ID          string  `json:"id"`
	DeviceID    string  `json:"device_id"`
	DeviceLabel *string `json:"device_label,omitempty"`
	CreatedAt   string  `json:"created_at"`
	ExpiresAt   string  `json:"expires_at"`
	Revoked     bool    `json:"revoked"`
}

// SessionRevokeOTPResponse is POST /sessions/revoke-otp.
type SessionRevokeOTPResponse struct {
	Status string `json:"status"`
}

// SessionRevokeRequestBody is POST /sessions/{sessionID}/revoke.
type SessionRevokeRequestBody struct {
	Code string `json:"code"`
}

// RoleDTO matches JSON encoding of domain.Role (stdlib uses struct field names as keys).
type RoleDTO struct {
	ID          string `json:"ID"`
	Name        string `json:"Name"`
	Description string `json:"Description"`
	CreatedAt   string `json:"CreatedAt"`
}

// RolesListResponse is GET /roles.
type RolesListResponse struct {
	Roles []RoleDTO `json:"roles"`
}

// CreateRoleRequestBody is POST /roles.
type CreateRoleRequestBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CreateRoleResponse is returned after creating a role.
type CreateRoleResponse struct {
	RoleID string `json:"role_id"`
}

// PatchRoleRequestBody is PATCH /roles/{roleID}/description.
type PatchRoleRequestBody struct {
	Description string `json:"description"`
}

// UserRoleDTO matches JSON encoding of domain.UserRole.
type UserRoleDTO struct {
	ID         string  `json:"ID"`
	UserID     string  `json:"UserID"`
	RoleID     string  `json:"RoleID"`
	Level      string  `json:"Level"`
	ValidFrom  string  `json:"ValidFrom"`
	ValidUntil *string `json:"ValidUntil,omitempty"`
	GrantedBy  *string `json:"GrantedBy,omitempty"`
}

// UserRolesListResponse is GET /users/{userID}/roles.
type UserRolesListResponse struct {
	UserRoles []UserRoleDTO `json:"user_roles"`
}

// AssignRoleRequestBody is POST /roles/{roleID}/members.
type AssignRoleRequestBody struct {
	UserID     string  `json:"user_id"`
	Level      string  `json:"level"`
	ValidUntil *string `json:"valid_until,omitempty"`
}

// RoleRequestCreateBody is POST /roles/{roleID}/requests.
type RoleRequestCreateBody struct {
	TargetUserID string `json:"target_user_id"`
}

// RoleRequestCreateResponse is returned when a role request is created.
type RoleRequestCreateResponse struct {
	RequestID string `json:"request_id"`
}

// RoleRequestRow matches JSON encoding of repository.RoleRequest.
type RoleRequestRow struct {
	ID           string  `json:"ID"`
	RequesterID  string  `json:"RequesterID"`
	TargetUserID string  `json:"TargetUserID"`
	RoleID       string  `json:"RoleID"`
	Status       string  `json:"Status"`
	DecidedBy    *string `json:"DecidedBy,omitempty"`
}

// RoleRequestsListResponse is GET /roles/{roleID}/requests.
type RoleRequestsListResponse struct {
	Requests []RoleRequestRow `json:"requests"`
}

// DecideRoleRequestBody is POST /role-requests/{requestID}/decide.
type DecideRoleRequestBody struct {
	Approve bool `json:"approve"`
}

// StepUp2FAStartRequestBody is POST /auth/step-up-2fa/start.
type StepUp2FAStartRequestBody struct {
	TTLSeconds int64 `json:"ttl_seconds"`
}

// StepUp2FAStartResponse is returned when a step-up 2FA challenge is started.
type StepUp2FAStartResponse struct {
	CorrelationID string `json:"correlation_id"`
}

// StepUp2FAStatusResponse is GET /auth/step-up-2fa/status.
type StepUp2FAStatusResponse struct {
	Status string `json:"status"`
}

// StepUp2FAExpireRequestBody is POST /auth/step-up-2fa/expire.
type StepUp2FAExpireRequestBody struct {
	CorrelationID string `json:"correlation_id"`
}

// AdminUserRow is one user in GET /admin/users.
type AdminUserRow struct {
	ID        string `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	Kind      string `json:"kind"`
	Superuser bool   `json:"superuser"`
	CreatedAt string `json:"created_at"`
}

// AdminUsersResponse is GET /admin/users.
type AdminUsersResponse struct {
	Users []AdminUserRow `json:"users"`
}

// HasRoleResponse is GET /me/has-role.
type HasRoleResponse struct {
	HasRole bool `json:"has_role"`
}
