// Multi-account support for the demo.
//
// Each account keeps its OWN refresh token (returned by the backend and stored
// client-side), so any signed-in account can refresh independently — switching
// between accounts just works, and a reload restores them all. This mirrors how
// native apps manage multiple accounts.
//
// Trade-off: storing refresh tokens in localStorage is less protected than an
// HttpOnly cookie (an XSS bug could read them). A production app would prefer
// server-side multi-session (one opaque cookie indexing several sessions). This
// is a demo, so we keep it simple and document the choice.
import { type MeUser, clearSession, onSessionChange, refresh, session, setTokens, setUser } from './api'
import { loadIdentity } from './store'

export interface Account {
  id: string
  login: string
  superuser: boolean
  email: string | null
  kind: string
  accessToken: string
  csrfToken: string
  refreshToken: string
  expiresAt: string
  deviceId: string
}

export interface Tokens {
  access_token: string
  csrf_token: string
  expires_at: string
  refresh_token: string
}

const KEY = 'accounts_v1'
let list: Account[] = restore()
let activeId = localStorage.getItem('active_account') || ''

const subs = new Set<() => void>()
let syncSuspended = false
export function suspendSync(v: boolean): void {
  syncSuspended = v
}
export function onAccountsChange(fn: () => void): () => void {
  subs.add(fn)
  return () => subs.delete(fn)
}
function emit(): void {
  persist()
  for (const fn of subs) fn()
}

export function accounts(): Account[] {
  return list
}
export function activeAccountId(): string {
  return activeId
}

function restore(): Account[] {
  try {
    return JSON.parse(localStorage.getItem(KEY) || '[]')
  } catch {
    return []
  }
}
function persist(): void {
  localStorage.setItem(KEY, JSON.stringify(list))
  localStorage.setItem('active_account', activeId)
}

// Keep the active account's stored tokens/profile in sync with the live session.
onSessionChange(() => {
  if (syncSuspended || !activeId || !session.user) return
  if (session.user.id !== activeId) return // ignore mid-login transitions
  const a = list.find((x) => x.id === activeId)
  if (!a) return
  a.accessToken = session.accessToken
  a.csrfToken = session.csrfToken
  a.refreshToken = session.refreshToken
  a.expiresAt = session.expiresAt
  a.login = session.user.login
  a.superuser = session.user.superuser
  a.email = session.user.email
  a.kind = session.user.kind
  persist()
})

function applyTokens(t: { accessToken: string; csrfToken: string; refreshToken: string; expiresAt: string }, deviceId: string): void {
  session.deviceId = deviceId
  session.refreshToken = t.refreshToken
  setTokens(t.accessToken, t.csrfToken, t.expiresAt)
}

/**
 * Apply freshly-issued tokens, load identity, and record the active account.
 * Sync is suspended during the transition so a previously-added account isn't
 * overwritten while the shared session flips.
 */
export async function completeSignIn(t: Tokens, deviceId: string): Promise<void> {
  suspendSync(true)
  try {
    applyTokens({ accessToken: t.access_token, csrfToken: t.csrf_token, refreshToken: t.refresh_token, expiresAt: t.expires_at }, deviceId)
    await loadIdentity()
    recordActiveLogin(deviceId)
  } finally {
    suspendSync(false)
  }
}

/** Record the just-authenticated session as an account and make it active. */
export function recordActiveLogin(deviceId: string): void {
  const u = session.user
  if (!u) return
  const acc: Account = {
    id: u.id,
    login: u.login,
    superuser: u.superuser,
    email: u.email,
    kind: u.kind,
    accessToken: session.accessToken,
    csrfToken: session.csrfToken,
    refreshToken: session.refreshToken,
    expiresAt: session.expiresAt,
    deviceId,
  }
  const i = list.findIndex((a) => a.id === u.id)
  if (i >= 0) list[i] = acc
  else list.push(acc)
  activeId = u.id
  emit()
}

/** Switch the active account to `id`, loading its cached tokens (refreshing if stale). */
export async function switchTo(id: string): Promise<void> {
  const a = list.find((x) => x.id === id)
  if (!a) return
  suspendSync(true)
  try {
    activeId = id
    applyTokens(a, a.deviceId)
    setUser({ id: a.id, login: a.login, email: a.email, kind: a.kind, superuser: a.superuser } as MeUser)
  } finally {
    suspendSync(false)
  }
  emit()
  // loadIdentity transparently refreshes this account's token if it's stale
  // (each account has its own refresh token), so switching always works.
  await loadIdentity().catch(() => {})
}

/** Sign out a single account (revoking its server session); switch to another if any remain. */
export async function signOutAccount(id: string, apiLogout: (token: string) => Promise<unknown>): Promise<void> {
  const acc = list.find((a) => a.id === id)
  if (acc) await apiLogout(acc.refreshToken).catch(() => {})
  const wasActive = id === activeId
  list = list.filter((a) => a.id !== id)
  if (wasActive) {
    activeId = ''
    if (list.length) {
      await switchTo(list[0].id)
    } else {
      clearSession()
      emit()
    }
  } else {
    emit()
  }
}

/** Sign out every account and clear all local state. */
export async function signOutAll(apiLogout: (token: string) => Promise<unknown>): Promise<void> {
  for (const a of list) await apiLogout(a.refreshToken).catch(() => {})
  list = []
  activeId = ''
  clearSession()
  emit()
}

/** On boot, restore the active account from its stored refresh token. */
export async function bootRestore(): Promise<void> {
  const active = list.find((a) => a.id === activeId) ?? list[0]
  if (!active) return
  activeId = active.id
  applyTokens(active, active.deviceId)
  setUser({ id: active.id, login: active.login, email: active.email, kind: active.kind, superuser: active.superuser } as MeUser)
  await refresh() // rotate to a fresh access token
  await loadIdentity().catch(() => {})
  emit()
}
