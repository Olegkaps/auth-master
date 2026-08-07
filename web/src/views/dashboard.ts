import { api, session } from '../api'
import { isSuperuser, store } from '../store'
import { navigate } from '../router'
import { badge, button, card, h, table } from '../ui'

export async function dashboardView(): Promise<HTMLElement> {
  const su = isSuperuser()
  const [roles, rolePage, userPage] = await Promise.all([
    api.listRoles(),
    api.searchRoles('', '', 1),
    su ? api.searchUsers('', '', 1).catch(() => null) : Promise.resolve(null),
  ])
  const roleName = (id: string): string => roles.find((r) => r.id === id)?.name ?? id.slice(0, 8)

  const u = session.user!
  const identity = card(
    'Your account',
    table(
      ['Field', 'Value'],
      [
        ['Login', h('strong', {}, u.login)],
        ['User ID', h('code', { class: 'mono' }, u.id)],
        ['Email', u.email ?? '—'],
        ['Kind', u.kind],
        ['Access', su ? badge('superuser', 'yellow') : badge('standard user', 'gray')],
      ],
    ),
  )

  const stat = (label: string, value: string | number, to?: string): HTMLElement =>
    h('div', { class: 'stat' + (to ? ' link' : ''), onclick: to ? () => navigate(to) : undefined }, h('div', { class: 'stat-value' }, String(value)), h('div', { class: 'stat-label' }, label))

  const stats = h(
    'div',
    { class: 'stat-grid' },
    stat('Roles in system', rolePage.total ?? roles.length, '/roles'),
    stat('Your memberships', store.myRoles.length, '/roles'),
    su ? stat('Users', userPage?.total ?? 0, '/admin/users') : stat('Active sessions', '→', '/sessions'),
  )

  const myRoles = card(
    'Your roles',
    store.myRoles.length
      ? table(
          ['Role', 'Level'],
          store.myRoles.map((r) => [
            roleName(r.roleId),
            r.level === 'role_admin'
              ? badge('role admin', 'blue')
              : badge(r.level === 'direct_member' ? 'direct member' : 'member', 'gray'),
          ]),
        )
      : h('div', { class: 'empty' }, 'You have no roles yet. Browse roles and request membership.'),
  )

  const actions = card(
    'Quick actions',
    h(
      'div',
      { class: 'btn-row' },
      button('Browse roles', () => navigate('/roles')),
      button('My sessions', () => navigate('/sessions'), 'secondary'),
      su && button('Invite a user', () => navigate('/admin/invites'), 'secondary'),
      su && button('Manage users', () => navigate('/admin/users'), 'secondary'),
    ),
  )

  return h(
    'div',
    { class: 'page', 'data-testid': 'dashboard' },
    h('div', { class: 'page-head' }, h('h2', { 'data-testid': 'welcome' }, `Welcome, ${u.login}`), h('p', { class: 'muted' }, 'This dashboard adapts to your permissions — sign in as a superuser to see admin panels.')),
    stats,
    h('div', { class: 'grid-2' }, identity, myRoles),
    actions,
  )
}
