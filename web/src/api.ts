// HTTP client for the demo app.
//
// This is a DEMONSTRATION frontend that shows how a real single-page app would
// consume the auth service: transparent token refresh, CSRF handling, an
// in-memory access token restored from the refresh cookie on reload, and typed
// endpoint wrappers. A production app would generate this client from the
// OpenAPI spec at /swagger/doc.json.

const API_BASE = '' // same-origin; the Vite dev server proxies /v1 to the backend.

// ---- Session state (in-memory; refresh token lives in an HttpOnly cookie) ----

export interface MeUser {
  id: string
  login: string
  email: string | null
  kind: string
  superuser: boolean
}

type Listener = () => void
const listeners = new Set<Listener>()

export const session = {
  accessToken: '',
  csrfToken: readCookie('csrf_token'),
  expiresAt: '',
  // refreshToken of the active account. Multi-account clients manage refresh
  // tokens per account, so any account can be refreshed regardless of the cookie.
  refreshToken: '',
  // Stable per-browser device id: re-logging into the same account reuses it, so
  // the backend upserts (replaces) the session and only the last one stays active.
  deviceId: localStorage.getItem('device_id') || crypto.randomUUID(),
  user: null as MeUser | null,
}
localStorage.setItem('device_id', session.deviceId)

export function onSessionChange(fn: Listener): () => void {
  listeners.add(fn)
  return () => listeners.delete(fn)
}
function emit(): void {
  for (const fn of listeners) fn()
}

export function isSignedIn(): boolean {
  return session.accessToken !== ''
}

export function setTokens(accessToken: string, csrfToken: string, expiresAt: string): void {
  session.accessToken = accessToken
  if (csrfToken) session.csrfToken = csrfToken
  if (expiresAt) session.expiresAt = expiresAt
  emit()
}

export function setUser(u: MeUser | null): void {
  session.user = u
  emit()
}

export function clearSession(): void {
  session.accessToken = ''
  session.csrfToken = ''
  session.expiresAt = ''
  session.refreshToken = ''
  session.user = null
  emit()
}

function readCookie(name: string): string {
  const m = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`))
  return m ? decodeURIComponent(m[1]) : ''
}

// ---- Low-level request ------------------------------------------------------

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

interface Opts {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  body?: unknown
  skipAuth?: boolean
  bearer?: string
  noRefresh?: boolean
}

function headers(o: Opts): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' }
  const bearer = o.bearer ?? (o.skipAuth ? '' : session.accessToken)
  if (bearer) h['Authorization'] = `Bearer ${bearer}`
  if (session.csrfToken && o.method && o.method !== 'GET') h['X-CSRF-Token'] = session.csrfToken
  return h
}

async function raw(path: string, o: Opts): Promise<Response> {
  return fetch(`${API_BASE}${path}`, {
    method: o.method ?? 'GET',
    headers: headers(o),
    credentials: 'include',
    body: o.body === undefined ? undefined : JSON.stringify(o.body),
  })
}

/** Decode the `sub` (user id) claim from a JWT without verifying its signature. */
export function decodeJwtSub(token: string): string {
  try {
    return JSON.parse(atob((token.split('.')[1] || '').replace(/-/g, '+').replace(/_/g, '/'))).sub || ''
  } catch {
    return ''
  }
}

/**
 * Rotate the active account's access token using its stored refresh token
 * (sent in the body — non-ambient, so no CSRF needed). Because each account
 * carries its own refresh token, any account can refresh regardless of the
 * shared cookie. The rotated refresh token is stored back on the session.
 */
export async function refresh(): Promise<boolean> {
  if (!session.refreshToken) return false
  const res = await fetch(`${API_BASE}/v1/auth/refresh`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_id: session.deviceId, device_label: deviceLabel(), refresh_token: session.refreshToken }),
  })
  if (!res.ok) return false
  const j = await res.json().catch(() => ({}))
  session.refreshToken = (j.refresh_token as string) || session.refreshToken
  setTokens((j.access_token as string) ?? '', '', j.expires_at ?? '')
  return true
}

// Called when the refresh token itself is dead — lets the app route to /login.
let onUnauthorized: () => void = () => {}
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn
}

function expiringSoon(): boolean {
  if (!session.expiresAt) return false
  const t = Date.parse(session.expiresAt)
  return Number.isFinite(t) && t - Date.now() < 15_000
}

async function call<T>(path: string, o: Opts = {}): Promise<T> {
  // Only requests that rely on our session access token can be refreshed;
  // skipAuth (public) and explicit bearer (introspection) must not.
  const canRefresh = !o.noRefresh && !o.skipAuth && !o.bearer && session.accessToken !== ''

  // Proactive: rotate a nearly-expired access token before spending a round trip.
  if (canRefresh && expiringSoon()) await refresh()

  let res = await raw(path, o)

  // Reactive: refresh on a stale signing key (rotation) or an expired token (401).
  const needsRefresh = canRefresh && (res.headers.get('X-Token-Stale') === '1' || res.status === 401)
  if (needsRefresh) {
    if (await refresh()) {
      res = await raw(path, o)
    } else {
      clearSession()
      onUnauthorized()
    }
  }

  const empty = res.status === 204 || res.headers.get('Content-Length') === '0'
  const data = empty ? null : await res.json().catch(() => null)
  if (!res.ok) {
    const msg = (data as { error?: string })?.error || `HTTP ${res.status}`
    throw new ApiError(res.status, msg)
  }
  return data as T
}

export function deviceLabel(): string {
  return navigator.userAgent.slice(0, 80)
}

// ---- Typed domain models (normalized to camelCase) --------------------------

export interface Role {
  id: string
  name: string
  description: string
  parentIds: string[]
}
export interface RoleMember {
  userId: string
  login: string
  email: string | null
  level: 'member' | 'role_admin'
}
export interface UserRole {
  id: string
  userId: string
  roleId: string
  level: 'member' | 'role_admin'
  validUntil: string | null
}
export interface RoleRequest {
  id: string
  requesterId: string
  targetUserId: string
  roleId: string
  status: string
}
export interface AdminUser {
  id: string
  login: string
  email: string | null
  kind: string
  superuser: boolean
  createdAt: string
}
export interface Session {
  id: string
  deviceId: string
  deviceLabel?: string
  createdAt: string
  expiresAt: string
  revoked: boolean
}

// ---- Endpoint wrappers ------------------------------------------------------

export const api = {
  // auth
  register: (invite_token: string, login: string, email: string, password: string) =>
    call<{ user_id: string }>('/v1/auth/register', { method: 'POST', skipAuth: true, body: { invite_token, login, email, password } }),
  previewInvite: (token: string) =>
    call<{ valid: boolean; email?: string; superuser?: boolean; expires_at?: string }>(`/v1/auth/registration-invite?token=${encodeURIComponent(token)}`, { skipAuth: true }),
  login: (login: string, password: string) =>
    call<{ otp_sent?: boolean; password_expired?: boolean; login_challenge?: string }>('/v1/auth/login', { method: 'POST', skipAuth: true, body: { login, password } }),
  verifyOtp: (challenge: string, code: string, deviceId: string) =>
    call<{ access_token: string; csrf_token: string; expires_at: string; refresh_token: string }>('/v1/auth/login/verify-otp', {
      method: 'POST',
      skipAuth: true,
      body: { challenge, code, device_id: deviceId, device_label: deviceLabel() },
    }),
  magicLinkStart: (login: string) =>
    call<{ status: string }>('/v1/auth/login/magic-link', { method: 'POST', skipAuth: true, body: { login } }),
  magicLinkVerify: (token: string, deviceId: string) =>
    call<{ access_token: string; csrf_token: string; expires_at: string; refresh_token: string }>('/v1/auth/login/magic-link/verify', {
      method: 'POST',
      skipAuth: true,
      body: { token, device_id: deviceId, device_label: deviceLabel() },
    }),
  logout: (refreshToken?: string) => call<null>('/v1/auth/logout', { method: 'POST', body: refreshToken ? { refresh_token: refreshToken } : {} }),
  changePassword2FAStart: () => call<{ status: string }>('/v1/auth/password/2fa', { method: 'POST', body: {} }),
  changePassword: (old_password: string, new_password: string, code: string) =>
    call<null>('/v1/auth/password', { method: 'POST', body: { old_password, new_password, code } }),
  passwordResetStart: (login: string) =>
    call<{ status: string }>('/v1/auth/password/reset/start', { method: 'POST', skipAuth: true, body: { login } }),
  passwordResetComplete: (login: string, code: string, new_password: string) =>
    call<null>('/v1/auth/password/reset/complete', { method: 'POST', skipAuth: true, body: { login, code, new_password } }),
  serviceToken: (login: string, secret: string) =>
    call<{ access_token: string; expires_at: string }>('/v1/auth/service-token', { method: 'POST', skipAuth: true, body: { login, secret } }),
  tokenInfo: (bearer: string) =>
    call<{ subject: string; login: string; kid: string; typ: string }>('/v1/auth/token/info', { bearer, skipAuth: !bearer }),

  // step-up 2fa
  stepUpStart: (ttl_seconds: number) =>
    call<{ correlation_id: string }>('/v1/auth/step-up-2fa/start', { method: 'POST', body: { ttl_seconds } }),
  stepUpStatus: (id: string) =>
    call<{ status: string }>(`/v1/auth/step-up-2fa/status?correlation_id=${encodeURIComponent(id)}`),
  stepUpComplete: (correlation_id: string, code: string) =>
    call<{ status: string }>('/v1/auth/step-up-2fa/complete', { method: 'POST', skipAuth: true, body: { correlation_id, code } }),
  stepUpExpire: (correlation_id: string) =>
    call<null>('/v1/auth/step-up-2fa/expire', { method: 'POST', body: { correlation_id } }),

  // me
  me: () => call<MeUser>('/v1/me'),
  hasRole: (name: string) => call<{ has_role: boolean }>(`/v1/me/has-role?role_name=${encodeURIComponent(name)}`),

  // sessions
  listSessions: () =>
    call<{ sessions: Array<{ id: string; device_id: string; device_label?: string; created_at: string; expires_at: string; revoked: boolean }> }>('/v1/sessions').then((r) =>
      r.sessions.map((s): Session => ({
        id: s.id,
        deviceId: s.device_id,
        deviceLabel: s.device_label,
        createdAt: s.created_at,
        expiresAt: s.expires_at,
        revoked: s.revoked,
      })),
    ),
  // Direct one-click revoke of your own session (no OTP — you're authenticated).
  revokeSession: (id: string) => call<null>(`/v1/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  // roles
  listRoles: () =>
    call<{ roles: Array<{ ID: string; Name: string; Description: string; ParentIDs?: string[] }> }>('/v1/roles').then((r) =>
      r.roles.map((x): Role => ({ id: x.ID, name: x.Name, description: x.Description, parentIds: x.ParentIDs ?? [] })),
    ),
  createRole: (name: string, description: string, parent_id?: string) =>
    call<{ role_id: string }>('/v1/roles', { method: 'POST', body: { name, description, parent_id: parent_id || '' } }),
  deleteRole: (roleId: string) => call<null>(`/v1/roles/${encodeURIComponent(roleId)}`, { method: 'DELETE' }),
  patchRole: (roleId: string, description: string) =>
    call<null>(`/v1/roles/${encodeURIComponent(roleId)}/description`, { method: 'PATCH', body: { description } }),
  setRoleParent: (roleId: string, parent_id: string) =>
    call<null>(`/v1/roles/${encodeURIComponent(roleId)}/parent`, { method: 'PATCH', body: { parent_id } }),
  mountRole: (roleId: string, parent_id: string) =>
    call<null>(`/v1/roles/${encodeURIComponent(roleId)}/mounts`, { method: 'POST', body: { parent_id } }),
  unmountRole: (roleId: string, parentId: string) =>
    call<null>(`/v1/roles/${encodeURIComponent(roleId)}/mounts/${encodeURIComponent(parentId)}`, { method: 'DELETE' }),
  listRoleMembers: (roleId: string) =>
    call<{ members: Array<{ user_id: string; login: string; email: string | null; level: string }> }>(`/v1/roles/${encodeURIComponent(roleId)}/members`).then((r) =>
      r.members.map((m): RoleMember => ({ userId: m.user_id, login: m.login, email: m.email, level: m.level as RoleMember['level'] })),
    ),
  userRoles: (userId: string) =>
    call<{ user_roles: Array<{ ID: string; UserID: string; RoleID: string; Level: string; ValidUntil: string | null }> }>(
      `/v1/users/${encodeURIComponent(userId)}/roles`,
    ).then((r) =>
      r.user_roles.map((x): UserRole => ({ id: x.ID, userId: x.UserID, roleId: x.RoleID, level: x.Level as UserRole['level'], validUntil: x.ValidUntil })),
    ),
  assignRole: (roleId: string, user_id: string, level: 'member' | 'role_admin', valid_until?: string | null) =>
    call<null>(`/v1/roles/${encodeURIComponent(roleId)}/members`, { method: 'POST', body: { user_id, level, valid_until: valid_until || null } }),
  removeRole: (roleId: string, userId: string) =>
    call<null>(`/v1/roles/${encodeURIComponent(roleId)}/members/${encodeURIComponent(userId)}`, { method: 'DELETE' }),
  requestRole: (roleId: string, target_user_id?: string) =>
    call<{ status: string; request_id?: string }>(`/v1/roles/${encodeURIComponent(roleId)}/requests`, { method: 'POST', body: { target_user_id: target_user_id || '' } }),
  listRoleRequests: (roleId: string) =>
    call<{ requests: Array<{ ID: string; RequesterID: string; TargetUserID: string; RoleID: string; Status: string }> }>(
      `/v1/roles/${encodeURIComponent(roleId)}/requests`,
    ).then((r) =>
      r.requests.map((x): RoleRequest => ({ id: x.ID, requesterId: x.RequesterID, targetUserId: x.TargetUserID, roleId: x.RoleID, status: x.Status })),
    ),
  decideRequest: (requestId: string, approve: boolean) =>
    call<null>(`/v1/role-requests/${encodeURIComponent(requestId)}/decide`, { method: 'POST', body: { approve } }),

  // admin
  listUsers: (limit = 100) =>
    call<{ users: AdminUser[] }>(`/v1/admin/users?limit=${limit}`).then((r) => r.users),
  createInvite: (email: string, ttl_seconds: number, superuser = false) =>
    call<{ token: string; expires_at: string; registration_url: string }>('/v1/admin/registration-invites', {
      method: 'POST',
      body: { email, ttl_seconds, superuser },
    }),
  rotateSigningKey: () => call<null>('/v1/admin/signing-keys/rotate', { method: 'POST' }),
}
