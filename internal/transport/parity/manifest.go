// Package parity is the checked-in contract linking every business HTTP route
// to its typed gRPC counterpart.
package parity

// AuthPolicy is the authentication contract for an exact RPC method. Unknown
// methods never inherit policy from their service name and are denied.
type AuthPolicy uint8

const (
	AuthUnknown AuthPolicy = iota
	AuthPublic
	AuthHuman
	AuthActor
)

type Route struct {
	HTTPMethod string
	HTTPPath   string
	RPC        string
	CSRF       bool
	Auth       AuthPolicy
}

var BusinessRoutes = []Route{
	{"GET", "/v1/auth/registration-invite", "/auth.v1.AuthService/PreviewRegistrationInvite", false, AuthPublic},
	{"POST", "/v1/auth/register", "/auth.v1.AuthService/Register", false, AuthPublic},
	{"POST", "/v1/auth/login", "/auth.v1.AuthService/LoginPassword", false, AuthPublic},
	{"POST", "/v1/auth/service-token", "/auth.v1.AuthService/IssueServiceToken", false, AuthPublic},
	{"POST", "/v1/auth/has-role", "/auth.v1.AuthService/CheckTokenRole", false, AuthPublic},
	{"POST", "/v1/auth/has-role-with-tag", "/auth.v1.AuthService/CheckTokenRoleWithTag", false, AuthPublic},
	{"GET", "/v1/auth/token/info", "/auth.v1.AuthService/InspectToken", false, AuthPublic},
	{"GET", "/v1/auth/token/verify-access", "/auth.v1.AuthService/VerifyAccessToken", false, AuthPublic},
	{"POST", "/v1/auth/login/verify-otp", "/auth.v1.AuthService/VerifyLoginOTP", false, AuthPublic},
	{"POST", "/v1/auth/login/magic-link", "/auth.v1.AuthService/StartMagicLink", false, AuthPublic},
	{"POST", "/v1/auth/login/magic-link/verify", "/auth.v1.AuthService/CompleteMagicLink", false, AuthPublic},
	{"POST", "/v1/auth/password/reset/start", "/auth.v1.AuthService/StartPasswordReset", false, AuthPublic},
	{"POST", "/v1/auth/password/reset/complete", "/auth.v1.AuthService/CompletePasswordReset", false, AuthPublic},
	{"POST", "/v1/auth/refresh", "/auth.v1.AuthService/Refresh", false, AuthPublic},
	{"POST", "/v1/auth/logout", "/auth.v1.AuthService/Logout", false, AuthPublic},
	{"POST", "/v1/auth/step-up-2fa/complete", "/auth.v1.AuthService/CompleteStepUp2FA", false, AuthPublic},
	{"GET", "/v1/me", "/auth.v1.IdentityService/GetMe", false, AuthHuman},
	{"GET", "/v1/me/has-role", "/auth.v1.IdentityService/CheckMyRole", false, AuthHuman},
	{"GET", "/v1/me/has-role-with-tag", "/auth.v1.IdentityService/CheckMyRoleWithTag", false, AuthHuman},
	{"GET", "/v1/me/role-access", "/auth.v1.IdentityService/ListMyRoleAccess", false, AuthHuman},
	{"POST", "/v1/auth/password/2fa", "/auth.v1.IdentityService/StartPasswordChangeOTP", false, AuthHuman},
	{"POST", "/v1/auth/password", "/auth.v1.IdentityService/ChangePassword", false, AuthHuman},
	{"POST", "/v1/auth/step-up-2fa/start", "/auth.v1.IdentityService/StartStepUp2FA", false, AuthHuman},
	{"GET", "/v1/auth/step-up-2fa/status", "/auth.v1.IdentityService/GetStepUp2FAStatus", false, AuthHuman},
	{"POST", "/v1/auth/step-up-2fa/expire", "/auth.v1.IdentityService/ExpireStepUp2FA", true, AuthHuman},
	{"GET", "/v1/sessions", "/auth.v1.SessionService/ListSessions", false, AuthHuman},
	{"DELETE", "/v1/sessions/{sessionID}", "/auth.v1.SessionService/RevokeOwnSession", false, AuthHuman},
	{"POST", "/v1/sessions/revoke-otp", "/auth.v1.SessionService/StartSessionRevokeOTP", false, AuthHuman},
	{"POST", "/v1/sessions/{sessionID}/revoke", "/auth.v1.SessionService/RevokeSessionWithOTP", false, AuthHuman},
	{"POST", "/v1/admin/registration-invites", "/auth.v1.AdminService/CreateRegistrationInvite", true, AuthActor},
	{"POST", "/v1/admin/service-accounts", "/auth.v1.AdminService/CreateServiceAccount", true, AuthActor},
	{"POST", "/v1/admin/signing-keys/rotate", "/auth.v1.AdminService/RotateSigningKey", true, AuthActor},
	{"GET", "/v1/admin/users", "/auth.v1.AdminService/ListUsers", false, AuthActor},
	{"POST", "/v1/admin/users/{userID}/ban", "/auth.v1.AdminService/BanUser", true, AuthActor},
	{"DELETE", "/v1/admin/users/{userID}/ban", "/auth.v1.AdminService/UnbanUser", true, AuthActor},
	{"GET", "/v1/roles", "/auth.v1.RoleService/ListRoles", false, AuthActor},
	{"POST", "/v1/roles", "/auth.v1.RoleService/CreateRole", true, AuthActor},
	{"DELETE", "/v1/roles/{roleID}", "/auth.v1.RoleService/DeleteRole", true, AuthActor},
	{"PATCH", "/v1/roles/{roleID}/description", "/auth.v1.RoleService/UpdateRoleDescription", true, AuthActor},
	{"PATCH", "/v1/roles/{roleID}/parent", "/auth.v1.RoleService/SetRoleParent", true, AuthActor},
	{"POST", "/v1/roles/{roleID}/mounts", "/auth.v1.RoleService/MountRole", true, AuthActor},
	{"DELETE", "/v1/roles/{roleID}/mounts/{parentID}", "/auth.v1.RoleService/UnmountRole", true, AuthActor},
	{"GET", "/v1/roles/{roleID}/subgroups", "/auth.v1.RoleService/ListSubgroups", false, AuthActor},
	{"POST", "/v1/roles/{roleID}/tags", "/auth.v1.RoleService/AddRoleTag", true, AuthActor},
	{"DELETE", "/v1/roles/{roleID}/tags", "/auth.v1.RoleService/DeleteRoleTag", true, AuthActor},
	{"PATCH", "/v1/roles/{roleID}/tags", "/auth.v1.RoleService/RenameRoleTag", true, AuthActor},
	{"GET", "/v1/users/{userID}/roles", "/auth.v1.RoleService/ListUserRoles", false, AuthActor},
	{"GET", "/v1/roles/{roleID}/members", "/auth.v1.RoleService/ListRoleMembers", false, AuthActor},
	{"POST", "/v1/roles/{roleID}/members", "/auth.v1.RoleService/AssignRole", true, AuthActor},
	{"POST", "/v1/roles/{roleID}/members/{userID}/tags", "/auth.v1.RoleService/GrantMembershipTag", true, AuthActor},
	{"DELETE", "/v1/roles/{roleID}/members/{userID}/tags", "/auth.v1.RoleService/RevokeMembershipTag", true, AuthActor},
	{"DELETE", "/v1/roles/{roleID}/members/{userID}", "/auth.v1.RoleService/RemoveRole", true, AuthActor},
	{"POST", "/v1/roles/{roleID}/requests", "/auth.v1.RoleService/RequestRole", true, AuthActor},
	{"GET", "/v1/roles/{roleID}/requests", "/auth.v1.RoleService/ListRoleRequests", false, AuthActor},
	{"POST", "/v1/role-requests/{requestID}/decide", "/auth.v1.RoleService/DecideRoleRequest", true, AuthActor},
}

var TransportOnlyRoutes = []Route{
	{"GET", "/healthz", "", false, AuthUnknown},
	{"GET", "/metrics", "", false, AuthUnknown},
	{"GET", "/swagger/*", "", false, AuthUnknown},
}

// HTTPRoutes is the complete HTTP surface indexed by its exact method and
// path. Construction validates both route kinds and panics on duplicates so a
// malformed manifest cannot silently weaken parity tests.
var HTTPRoutes = mustHTTPRoutes(BusinessRoutes, TransportOnlyRoutes)

// RPCPolicies is derived once from BusinessRoutes and therefore cannot drift
// from HTTP/gRPC parity. Construction panics on duplicate or missing policy.
var RPCPolicies = mustRPCPolicies(BusinessRoutes)

func mustRPCPolicies(routes []Route) map[string]AuthPolicy {
	policies := make(map[string]AuthPolicy, len(routes))
	for _, route := range routes {
		if route.RPC == "" || route.Auth == AuthUnknown {
			panic("business route has missing RPC authentication policy")
		}
		if _, exists := policies[route.RPC]; exists {
			panic("duplicate RPC in parity manifest: " + route.RPC)
		}
		policies[route.RPC] = route.Auth
	}
	return policies
}

func mustHTTPRoutes(business, transport []Route) map[string]Route {
	routes := make(map[string]Route, len(business)+len(transport))
	add := func(route Route, businessRoute bool) {
		if route.HTTPMethod == "" || route.HTTPPath == "" {
			panic("parity manifest route has missing HTTP method or path")
		}
		if businessRoute {
			if route.RPC == "" || route.Auth == AuthUnknown {
				panic("business route has missing RPC authentication policy")
			}
		} else if route.RPC != "" || route.Auth != AuthUnknown || route.CSRF {
			panic("transport-only route has business semantics")
		}
		key := route.HTTPMethod + " " + route.HTTPPath
		if _, exists := routes[key]; exists {
			panic("duplicate HTTP route in parity manifest: " + key)
		}
		routes[key] = route
	}
	for _, route := range business {
		add(route, true)
	}
	for _, route := range transport {
		add(route, false)
	}
	return routes
}
