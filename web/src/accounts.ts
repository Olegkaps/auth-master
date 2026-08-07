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
import { ApiError, type MeUser, clearSession, onSessionChange, refresh, session, setTokens, setUser } from './api'
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

export class RetryableAccountError extends Error {}

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

function applyCachedAccount(account: Account): void {
  suspendSync(true)
  try {
    activeId = account.id
    applyTokens(account, account.deviceId)
    setUser({ id: account.id, login: account.login, email: account.email, kind: account.kind, superuser: account.superuser } as MeUser)
  } finally {
    suspendSync(false)
  }
  emit()
}

function isDefinitiveInvalid(error: unknown): boolean {
  return error instanceof ApiError && error.status === 401
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
  const previousId = activeId
	applyCachedAccount(a)
  try {
		const outcome = await refresh()
		if (outcome.kind === 'invalid') throw new ApiError(401, 'invalid refresh session')
		if (outcome.kind === 'transient') throw new RetryableAccountError(`Session for ${a.login} is temporarily unavailable; retry the switch.`)
    await loadIdentity()
    emit()
	} catch (error) {
		if (!isDefinitiveInvalid(error)) {
			const fallback = list.find((account) => account.id === previousId) ?? a
			applyCachedAccount(fallback)
			if (error instanceof RetryableAccountError) throw error
			throw new RetryableAccountError(`Session for ${a.login} is temporarily unavailable; retry the switch.`)
		}
    // A saved account can outlive its server session (revocation, database
    // reset, or expiry). Remove the dead entry and restore the prior account
    // instead of leaving an unusable duplicate in the account picker.
    list = list.filter((account) => account.id !== id)
    activeId = ''
    clearSession()
    emit()
    const fallback = list.find((account) => account.id === previousId) ?? list[0]
    if (fallback) await switchTo(fallback.id)
    throw new Error(`Session for ${a.login} has expired`)
  }
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
	applyCachedAccount(active)
  try {
		const outcome = await refresh()
		if (outcome.kind === 'invalid') throw new ApiError(401, 'invalid refresh session')
		if (outcome.kind === 'transient') return
    await loadIdentity()
    emit()
	} catch (error) {
		if (!isDefinitiveInvalid(error)) {
			applyCachedAccount(active)
			return
		}
    list = list.filter((account) => account.id !== active.id)
    activeId = ''
    clearSession()
    emit()
    if (list[0]) await switchTo(list[0].id).catch(() => {})
  }
}
