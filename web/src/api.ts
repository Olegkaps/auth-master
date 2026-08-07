// HTTP client for the demo app.
//
// This is a DEMONSTRATION frontend that shows how a real single-page app would
// consume the auth service: transparent token refresh, CSRF handling, an
// in-memory access token restored from the refresh cookie on reload, and typed
// endpoint wrappers. A production app would generate this client from the
// OpenAPI spec at /swagger/doc.json.

import { classifyRefreshResponse, type RefreshOutcome } from './refresh-outcome.js'
import { singleFlightByKey } from './single-flight.js'

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
  const csrfToken = readCookie('csrf_token') || session.csrfToken
  if (csrfToken && o.method && o.method !== 'GET') h['X-CSRF-Token'] = csrfToken
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
const refreshByToken = singleFlightByKey<string, RefreshOutcome>(async (refreshToken) => {
  try {
    const res = await fetch(`${API_BASE}/v1/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: session.deviceId, device_label: deviceLabel(), refresh_token: refreshToken }),
    })
    const payload: unknown = await res.json().catch(() => null)
    const outcome = classifyRefreshResponse(res.status, payload)
    // An account switch may finish while this request is in flight. Never let
    // an old account's response overwrite the newly active account.
    if (outcome.kind === 'ok' && session.refreshToken === refreshToken) {
      session.refreshToken = outcome.refreshToken
      setTokens(outcome.accessToken, '', outcome.expiresAt)
    }
    return outcome
  } catch {
    return { kind: 'transient', status: 0, reason: 'network error' }
  }
})

export async function refresh(): Promise<RefreshOutcome> {
  const refreshToken = session.refreshToken
  if (!refreshToken) return { kind: 'invalid', status: 0 }
  return refreshByToken(refreshToken)
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
  if (canRefresh && expiringSoon()) {
    const proactive = await refresh()
    if (proactive.kind === 'invalid') {
      clearSession()
      onUnauthorized()
    }
  }

  let res = await raw(path, o)

  // Reactive: refresh on a stale signing key (rotation) or an expired token (401).
  const needsRefresh = canRefresh && (res.headers.get('X-Token-Stale') === '1' || res.status === 401)
  if (needsRefresh) {
    const outcome = await refresh()
    if (outcome.kind === 'ok') {
      res = await raw(path, o)
    } else if (outcome.kind === 'invalid') {
      clearSession()
      onUnauthorized()
    } else {
      throw new ApiError(outcome.status, `Session refresh temporarily unavailable: ${outcome.reason}`)
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
	  tags: string[]
}
export interface RoleMember {
  userId: string
  login: string
  email: string | null
  level: 'direct_member' | 'member' | 'role_admin'
	  tags: string[]
}
export interface UserRole {
  id: string
  userId: string
  roleId: string
  level: 'direct_member' | 'member' | 'role_admin'
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
	  bannedAt: string | null
	  banReason: string
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
  roleAccess: () => call<{ roles: Array<{ role_id: string; can_manage: boolean }> }>('/v1/me/role-access'),

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
  searchRoles: (q = '', cursor = '', pageSize = 25) =>
	  call<{ roles: Array<{ ID: string; Name: string; Description: string; ParentIDs?: string[]; Tags?: string[] }>; total: number | null; next_cursor: string; page_size: number }>(`/v1/roles?q=${encodeURIComponent(q)}&cursor=${encodeURIComponent(cursor)}&page_size=${pageSize}`).then((r) => ({ ...r, roles: r.roles.map((x): Role => ({ id: x.ID, name: x.Name, description: x.Description, parentIds: x.ParentIDs ?? [], tags: x.Tags ?? [] })) })),
  listRoles: async () => {
    const roles: Role[] = []
    let cursor = ''
    do {
      const page = await api.searchRoles('', cursor, 100)
      roles.push(...page.roles)
      cursor = page.next_cursor
    } while (cursor)
    return roles
  },
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
  listSubgroups: (roleId: string, recursive = false) => call<{ roles: Array<{ ID: string; Name: string; Description: string; ParentIDs?: string[]; Tags?: string[] }> }>(`/v1/roles/${encodeURIComponent(roleId)}/subgroups?recursive=${recursive}`).then((r) => r.roles.map((x) => ({ id: x.ID, name: x.Name, description: x.Description, parentIds: x.ParentIDs ?? [], tags: x.Tags ?? [] }))),
	addRoleTag: (roleId: string, tag: string) => call<null>(`/v1/roles/${encodeURIComponent(roleId)}/tags`, { method: 'POST', body: { tag } }),
	deleteRoleTag: (roleId: string, tag: string) => call<null>(`/v1/roles/${encodeURIComponent(roleId)}/tags`, { method: 'DELETE', body: { tag } }),
	renameRoleTag: (roleId: string, old_tag: string, new_tag: string) => call<null>(`/v1/roles/${encodeURIComponent(roleId)}/tags`, { method: 'PATCH', body: { old_tag, new_tag } }),
  listRoleMembers: (roleId: string) =>
    call<{ members: Array<{ user_id: string; login: string; email: string | null; level: string; tags: string[] }> }>(`/v1/roles/${encodeURIComponent(roleId)}/members`).then((r) =>
      r.members.map((m): RoleMember => ({ userId: m.user_id, login: m.login, email: m.email, level: m.level as RoleMember['level'], tags: m.tags ?? [] })),
    ),
  userRoles: (userId: string) =>
    call<{ user_roles: Array<{ ID: string; UserID: string; RoleID: string; Level: string; ValidUntil: string | null }> }>(
      `/v1/users/${encodeURIComponent(userId)}/roles`,
    ).then((r) =>
      r.user_roles.map((x): UserRole => ({ id: x.ID, userId: x.UserID, roleId: x.RoleID, level: x.Level as UserRole['level'], validUntil: x.ValidUntil })),
    ),
  assignRole: (roleId: string, user_id: string, level: 'direct_member' | 'member' | 'role_admin', valid_until?: string | null, tag_grants?: string[]) =>
	  call<null>(`/v1/roles/${encodeURIComponent(roleId)}/members`, { method: 'POST', body: { user_id, level, valid_until: valid_until || null, ...(tag_grants === undefined ? {} : { tag_grants }) } }),
	addUserRoleTag: (roleId: string, userId: string, tag: string) => call<null>(`/v1/roles/${encodeURIComponent(roleId)}/members/${encodeURIComponent(userId)}/tags`, { method: 'POST', body: { tag } }),
	deleteUserRoleTag: (roleId: string, userId: string, tag: string) => call<null>(`/v1/roles/${encodeURIComponent(roleId)}/members/${encodeURIComponent(userId)}/tags`, { method: 'DELETE', body: { tag } }),
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
  searchUsers: (q = '', cursor = '', pageSize = 25) => call<{ users: Array<{ id: string; login: string; email: string | null; kind: string; superuser: boolean; banned_at: string | null; ban_reason: string; created_at: string }>; total: number | null; next_cursor: string; page_size: number }>(`/v1/admin/users?q=${encodeURIComponent(q)}&cursor=${encodeURIComponent(cursor)}&page_size=${pageSize}`).then((r) => ({ ...r, users: r.users.map((u) => ({ id: u.id, login: u.login, email: u.email, kind: u.kind, superuser: u.superuser, bannedAt: u.banned_at, banReason: u.ban_reason, createdAt: u.created_at })) })),
  listUsers: async (limit = Number.MAX_SAFE_INTEGER) => {
    const users: AdminUser[] = []
    let cursor = ''
    do {
      const page = await api.searchUsers('', cursor, Math.min(100, limit - users.length))
      users.push(...page.users)
      cursor = page.next_cursor
    } while (cursor && users.length < limit)
    return users
  },
  banUser: (userId: string, reason: string) => call<null>(`/v1/admin/users/${encodeURIComponent(userId)}/ban`, { method: 'POST', body: { reason } }),
  unbanUser: (userId: string) => call<null>(`/v1/admin/users/${encodeURIComponent(userId)}/ban`, { method: 'DELETE' }),
  createInvite: (email: string, ttl_seconds: number, superuser = false) =>
    call<{ token: string; expires_at: string; registration_url: string }>('/v1/admin/registration-invites', {
      method: 'POST',
      body: { email, ttl_seconds, superuser },
    }),
  rotateSigningKey: () => call<null>('/v1/admin/signing-keys/rotate', { method: 'POST' }),
}
