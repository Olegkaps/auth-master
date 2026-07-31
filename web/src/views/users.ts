import { api, type AdminUser, type Role } from '../api'
import { navigate } from '../router'
import { badge, button, card, field, h, modal, run, select, table, toast } from '../ui'

export async function usersView(): Promise<HTMLElement> {
  const [users, roles] = await Promise.all([api.listUsers(500), api.listRoles()])
  const roleName = (id: string): string => roles.find((r) => r.id === id)?.name ?? id.slice(0, 8)

  const rows = users.map((u) => [
    h('strong', {}, u.login),
    u.email ?? '—',
    u.kind,
    u.superuser ? badge('superuser', 'yellow') : badge(u.kind, 'gray'),
    h(
      'div',
      { class: 'btn-row' },
      button('Roles', () => viewRolesModal(u, roleName), 'secondary', { class: 'btn secondary small' }),
      button('Assign role', () => assignModal(u, roles), 'primary', { class: 'btn primary small' }),
      button('Copy ID', () => {
        void navigator.clipboard?.writeText(u.id)
        toast('User ID copied.', 'info')
      }, 'ghost', { class: 'btn ghost small' }),
    ),
  ])

  return h(
    'div',
    { class: 'page' },
    h(
      'div',
      { class: 'page-head row-between' },
      h('div', {}, h('h2', {}, 'Users'), h('p', { class: 'muted' }, `${users.length} users. Superuser-only view.`)),
      button('Invite user', () => navigate('/admin/invites'), 'secondary'),
    ),
    card(null, table(['Login', 'Email', 'Kind', 'Access', 'Actions'], rows)),
  )
}

async function viewRolesModal(u: AdminUser, roleName: (id: string) => string): Promise<void> {
  const body = h('div', {}, h('p', { class: 'muted small' }, `Roles held by ${u.login}.`))
  const close = modal(`Roles · ${u.login}`, body, [button('Close', () => close(), 'ghost')])
  const urs = await api.userRoles(u.id).catch(() => [])
  body.append(
    urs.length
      ? table(['Role', 'Level'], urs.map((r) => [roleName(r.roleId), r.level === 'role_admin' ? badge('role admin', 'blue') : badge('member', 'gray')]))
      : h('div', { class: 'empty' }, 'No roles.'),
  )
}

function assignModal(u: AdminUser, roles: Role[]): void {
  if (roles.length === 0) {
    toast('No roles exist yet — create one first.', 'err')
    return
  }
  const role = select(roles.map((r) => [r.id, r.name]))
  const level = select([
    ['member', 'member'],
    ['role_admin', 'role_admin'],
  ])
  const body = h('div', {}, h('p', { class: 'muted small' }, `Grant a role to ${u.login}.`), field('Role', role), field('Level', level))
  const close = modal('Assign role', body, [
    button('Cancel', () => close(), 'ghost'),
    button('Assign', async () => {
      const r = await run(api.assignRole(role.value, u.id, level.value as 'member' | 'role_admin'), `Assigned ${u.login} to role.`)
      if (r !== undefined) close()
    }),
  ])
}
