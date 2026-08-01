// App-level derived state: who am I, which roles do I hold, and what am I
// allowed to do. Kept separate from the raw HTTP client so views can ask
// permission questions ("can I approve requests for this role?") without
// re-deriving the logic each time.
import { api, session, setUser, type UserRole } from './api'

export const store = {
  myRoles: [] as UserRole[],
}

/** Load /me and the caller's role memberships. Call after sign-in and on boot. */
export async function loadIdentity(): Promise<void> {
  const me = await api.me()
  try {
    store.myRoles = await api.userRoles(me.id)
  } catch {
    store.myRoles = []
  }
  setUser(me) // triggers session listeners so the shell repaints with admin nav
}

export function isSuperuser(): boolean {
  return session.user?.superuser === true
}

export function isRoleAdmin(roleId: string): boolean {
  return store.myRoles.some((r) => r.roleId === roleId && r.level === 'role_admin')
}

export function isMember(roleId: string): boolean {
  return store.myRoles.some((r) => r.roleId === roleId)
}

/** Mirrors the backend CanAssignRole check for gating admin UI. */
export function canManageRole(roleId: string): boolean {
  return isSuperuser() || isRoleAdmin(roleId)
}
