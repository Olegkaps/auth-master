import { api, type AdminUser, type Role } from '../api'
import { navigate } from '../router'
import { badge, button, card, field, h, modal, run, select, table, textInput, toast } from '../ui'

export async function usersView(): Promise<HTMLElement> {
	const page = h('div', { class: 'page' })
	let currentPage = 1
	let cursors = ['']
	let total = 0
	let requestVersion = 0
	const search = textInput({ placeholder: 'Search login or email…', 'data-testid': 'users-search' })
	const load = async (): Promise<void> => {
	const version = ++requestVersion
	const query = search.value
	const cursor = cursors[currentPage - 1]
	const [result, roles] = await Promise.all([api.searchUsers(query, cursor, 25), api.listRoles()])
	if (version !== requestVersion) return
	const { users } = result
	if (result.total !== null) total = result.total
  const roleName = (id: string): string => roles.find((r) => r.id === id)?.name ?? id.slice(0, 8)

	const rows = users.map((u) => [
    h('strong', {}, u.login),
    u.email ?? '—',
    u.kind,
		u.bannedAt ? badge('banned', 'red') : u.superuser ? badge('superuser', 'yellow') : badge(u.kind, 'gray'),
    h(
      'div',
      { class: 'btn-row' },
      button('Roles', () => viewRolesModal(u, roleName), 'secondary', { class: 'btn secondary small' }),
		button('Assign role', () => assignModal(u, roles), 'primary', { class: 'btn primary small' }),
		u.bannedAt ? button('Unban', async () => { if (await run(api.unbanUser(u.id), 'User unbanned.') !== undefined) await load() }, 'secondary', { class: 'btn secondary small' }) : button('Ban', async () => { if (await run(api.banUser(u.id, 'Banned by administrator'), 'User banned.') !== undefined) await load() }, 'danger', { class: 'btn danger small', 'data-testid': `ban-${u.login}` }),
      button('Copy ID', () => {
        void navigator.clipboard?.writeText(u.id)
        toast('User ID copied.', 'info')
      }, 'ghost', { class: 'btn ghost small' }),
    ),
  ])

	page.replaceChildren(
    h(
      'div',
      { class: 'page-head row-between' },
		h('div', {}, h('h2', {}, 'Users'), h('p', { class: 'muted' }, `${total} users. Superuser-only view.`)),
      button('Invite user', () => navigate('/admin/invites'), 'secondary'),
    ),
	field('Autocomplete / filter', search),
	card(null, table(['Login', 'Email', 'Kind', 'Access', 'Actions'], rows)),
	h('div', { class: 'btn-row' }, button('Previous', async () => { if (currentPage > 1) { currentPage--; await load() } }, 'secondary'), h('span', {}, `Page ${currentPage} of ${Math.max(1, Math.ceil(total / 25))}`), button('Next', async () => { if (result.next_cursor) { cursors[currentPage] = result.next_cursor; currentPage++; await load() } }, 'secondary')),
	)
	}
	search.addEventListener('input', () => { currentPage = 1; cursors = ['']; void load() })
	await load()
	return page
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
	role.dataset.testid = 'assign-role-select'
  const level = select([
	['direct_member', 'direct member (no inheritance)'],
    ['member', 'member'],
    ['role_admin', 'role_admin'],
  ])
	const tags = textInput({ placeholder: 'read, write', 'data-testid': 'assign-role-tags' })
	const body = h('div', {}, h('p', { class: 'muted small' }, `Grant a role to ${u.login}.`), field('Role', role), field('Level', level), field('Tags', tags, 'Choose only tags configured for the selected role'))
  const close = modal('Assign role', body, [
    button('Cancel', () => close(), 'ghost'),
	button('Assign', async () => {
	  const selectedTags = tags.value.split(',').map((x) => x.trim()).filter(Boolean)
	  const r = await run(api.assignRole(role.value, u.id, level.value as 'direct_member' | 'member' | 'role_admin', null, selectedTags), `Assigned ${u.login} to role.`)
	  if (r !== undefined) {
		close()
	  }
	}, 'primary', { 'data-testid': 'assign-role-submit' }),
  ])
}
