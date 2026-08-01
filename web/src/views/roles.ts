import { api, session, type Role } from '../api'
import { canManageRole, isMember, isRoleAdmin, isSuperuser, loadIdentity } from '../store'
import { badge, button, card, field, h, modal, run, select, shortId, table, textInput, toast } from '../ui'

export async function rolesView(): Promise<HTMLElement> {
  const page = h('div', { class: 'page', 'data-testid': 'roles-page' })

  const reload = async (): Promise<void> => {
    const roles = await api.listRoles()
    render(page, roles, reload)
  }
  await reload()
  return page
}

function myStatus(roleId: string): HTMLElement {
  if (isRoleAdmin(roleId)) return badge('role admin', 'blue')
  if (isMember(roleId)) return badge('member', 'green')
  return h('span', { class: 'muted small' }, '—')
}

function render(page: HTMLElement, roles: Role[], reload: () => Promise<void>): void {
  const nameOf = (id: string): string => roles.find((r) => r.id === id)?.name ?? id.slice(0, 8)

  const head = h(
    'div',
    { class: 'page-head row-between' },
    h('div', {}, h('h2', {}, 'Roles'), h('p', { class: 'muted' }, 'Mount a role under multiple parents. Membership and administrator authority inherit through every parent path.')),
    isSuperuser() ? button('+ Create role', () => createRoleModal(roles, reload), 'primary', { 'data-testid': 'create-role-btn' }) : null,
  )

  const rows = roles.map((r) => {
    const actions = h('div', { class: 'btn-row' })
    if (!isMember(r.id) && !isRoleAdmin(r.id)) {
      actions.append(button('Request', () => requestMembership(r, reload), 'secondary', { class: 'btn secondary small', 'data-testid': `request-${r.name}` }))
    }
    if (canManageRole(r.id)) {
      actions.append(button('Manage', () => manageRoleModal(r, roles, reload), 'primary', { class: 'btn primary small', 'data-testid': `manage-${r.name}` }))
    }
    return [h('strong', {}, r.name), r.parentIds.length ? r.parentIds.map(nameOf).join(', ') : '—', h('span', { class: 'muted small' }, r.description || '—'), myStatus(r.id), actions]
  })

  page.replaceChildren(head, card(null, table(['Role', 'Parent', 'Description', 'Your status', 'Actions'], rows)))
}

async function requestMembership(role: Role, reload: () => Promise<void>): Promise<void> {
  const r = await run(api.requestRole(role.id))
  if (!r) return
  if (r.status === 'granted') {
    toast(`Granted membership in “${role.name}” (you're a manager — no approval needed).`, 'ok')
    await loadIdentity()
    await reload()
  } else {
    toast(`Requested membership in “${role.name}” — awaiting approval.`, 'info')
  }
}

function parentSelect(roles: Role[], exclude?: string): HTMLSelectElement {
  const opts: Array<[string, string]> = [['', '— none —']]
  for (const r of roles) if (r.id !== exclude) opts.push([r.id, r.name])
  const sel = select(opts)
  return sel
}

function createRoleModal(roles: Role[], reload: () => Promise<void>): void {
  const name = textInput({ placeholder: 'editors', 'data-testid': 'role-name-input' })
  const desc = textInput({ placeholder: 'Can edit content', 'data-testid': 'role-desc-input' })
  const parent = parentSelect(roles)
  const body = h('div', {}, field('Name', name), field('Description', desc), field('Parent role (optional)', parent, 'Admins of the parent inherit admin here'))
  const close = modal('Create role', body, [
    button('Cancel', () => close(), 'ghost'),
    button('Create', async () => {
      const r = await run(api.createRole(name.value.trim(), desc.value.trim(), parent.value || undefined), 'Role created.')
      if (r) {
        close()
        await reload()
      }
    }, 'primary', { 'data-testid': 'role-create-submit' }),
  ])
}

async function manageRoleModal(role: Role, roles: Role[], reload: () => Promise<void>): Promise<void> {
  const body = h('div', { class: 'stack' })
  const close = modal(`Manage · ${role.name}`, body, [button('Close', () => close(), 'ghost')])

  // Members (admins first) with per-row promote/remove actions
  const membersBox = card('Members', h('div', { class: 'muted small' }, 'Loading…'))
  body.append(membersBox)
  await renderMembers(role, membersBox, reload)

  // Description
  const desc = textInput({ value: role.description })
  body.append(
    card(
      'Description',
      field('Text', desc),
      button('Save description', async () => {
        const r = await run(api.patchRole(role.id, desc.value.trim()), 'Description updated.')
        if (r !== undefined) await reload()
      }, 'secondary'),
    ),
  )

  // Hierarchy (superuser only — matches backend)
  if (isSuperuser()) {
    const parent = parentSelect(roles, role.id)
    parent.dataset.testid = 'mount-parent-select'
    const mounted = h('div', { class: 'stack', 'data-testid': 'role-mounts' })
    const renderMounts = (): void => {
      mounted.replaceChildren(...(role.parentIds.length
        ? role.parentIds.map((parentId) => h('div', { class: 'row-between' }, h('span', {}, roles.find((r) => r.id === parentId)?.name ?? shortId(parentId)), button('Unmount', async () => {
            const result = await run(api.unmountRole(role.id, parentId), 'Role unmounted.')
            if (result !== undefined) { role.parentIds = role.parentIds.filter((id) => id !== parentId); renderMounts(); await reload() }
          }, 'danger', { class: 'btn danger small', 'data-testid': `unmount-${parentId}` })))
        : [h('span', { class: 'muted small' }, 'No mounts.')]))
    }
    renderMounts()
    body.append(
      card(
        'Mounts',
        mounted,
        field('Additional parent role', parent, 'A role can have multiple parents; cycles are rejected'),
        button('Mount', async () => {
          if (!parent.value || role.parentIds.includes(parent.value)) return
          const result = await run(api.mountRole(role.id, parent.value), 'Role mounted.')
          if (result !== undefined) { role.parentIds.push(parent.value); renderMounts(); await reload() }
        }, 'secondary', { 'data-testid': 'mount-role-btn' }),
      ),
    )
  }

  // Add a member by id (removal/level changes are done from the member list above)
  const assignUser = textInput({ placeholder: 'user UUID', 'data-testid': 'assign-user-id' })
  const level = select([
    ['member', 'member'],
    ['role_admin', 'role_admin'],
  ])
  body.append(
    card(
      'Add member',
      field('User id', assignUser, 'Tip: copy an id from the Users page'),
      field('Level', level),
      button('Add', async () => {
        const uid = assignUser.value.trim()
        const r = await run(api.assignRole(role.id, uid, level.value as 'member' | 'role_admin'), 'Member added.')
        if (r !== undefined) {
          if (uid === session.user?.id) await loadIdentity()
          assignUser.value = ''
          await renderMembers(role, membersBox, reload)
        }
      }, 'secondary', { 'data-testid': 'add-member-btn' }),
    ),
  )

  // Pending requests
  const reqBox = card('Pending requests', h('div', { class: 'muted small' }, 'Loading…'))
  body.append(reqBox)
  await renderRequests(role, reqBox, membersBox, reload)

  // Danger zone: delete the role (superuser only)
  if (isSuperuser()) {
    body.append(
      card(
        'Danger zone',
        h('p', { class: 'muted small' }, 'Deleting a role removes its memberships, requests, and mount edges.'),
        button('Delete role', async () => {
          const confirmBody = h('p', {}, `Delete role “${role.name}”? This cannot be undone.`)
          const confirmClose = modal('Delete role', confirmBody, [
            button('Cancel', () => confirmClose(), 'ghost'),
            button('Delete', async () => {
              const r = await run(api.deleteRole(role.id), 'Role deleted.')
              if (r !== undefined) {
                confirmClose()
                close()
                await reload()
              }
            }, 'danger', { 'data-testid': 'confirm-delete-role' }),
          ])
        }, 'danger', { 'data-testid': 'delete-role-btn' }),
      ),
    )
  }
}

async function renderMembers(role: Role, box: HTMLElement, reload: () => Promise<void>): Promise<void> {
  const members = await api.listRoleMembers(role.id).catch(() => [])
  const manage = canManageRole(role.id)
  const refreshAll = async (): Promise<void> => {
    await renderMembers(role, box, reload)
    await reload() // your own status/permissions may have changed
  }
  const list = members.length
    ? table(
        ['User', 'Login', 'Email', 'Level', ...(manage ? ['Actions'] : [])],
        members.map((m) => {
          const cells: (HTMLElement | string)[] = [
            shortId(m.userId),
            m.login,
            m.email ?? '—',
            m.level === 'role_admin' ? badge('role admin', 'blue') : badge('member', 'gray'),
          ]
          if (manage) {
            const toLevel = m.level === 'role_admin' ? 'member' : 'role_admin'
            cells.push(
              h(
                'div',
                { class: 'btn-row' },
                button(m.level === 'role_admin' ? 'Make member' : 'Make admin', async () => {
                  const r = await run(api.assignRole(role.id, m.userId, toLevel), `${m.login} is now ${toLevel}.`)
                  if (r !== undefined) await refreshAll()
                }, 'secondary', { class: 'btn secondary small', 'data-testid': `setlevel-${m.login}` }),
                button('Remove', async () => {
                  const r = await run(api.removeRole(role.id, m.userId), `Removed ${m.login}.`)
                  if (r !== undefined) await refreshAll()
                }, 'danger', { class: 'btn danger small', 'data-testid': `remove-${m.login}` }),
              ),
            )
          }
          return cells
        }),
      )
    : h('div', { class: 'empty' }, 'No members yet.')
  box.replaceChildren(h('h3', { class: 'panel-title' }, `Members (${members.length})`), list)
}

async function renderRequests(role: Role, box: HTMLElement, membersBox: HTMLElement, reload: () => Promise<void>): Promise<void> {
  const reqs = await api.listRoleRequests(role.id).catch(() => [])
  const list = reqs.length
    ? table(
        ['Request', 'Target user', 'Status', 'Decision'],
        reqs.map((rq) => [
          shortId(rq.id),
          shortId(rq.targetUserId),
          badge(rq.status, 'yellow'),
          h(
            'div',
            { class: 'btn-row' },
            button('Approve', async () => {
              await run(api.decideRequest(rq.id, true), 'Approved — membership granted.')
              await renderRequests(role, box, membersBox, reload)
              await renderMembers(role, membersBox, reload)
            }, 'primary', { class: 'btn primary small', 'data-testid': `approve-${rq.id}` }),
            button('Reject', async () => {
              await run(api.decideRequest(rq.id, false), 'Rejected.')
              await renderRequests(role, box, membersBox, reload)
            }, 'danger', { class: 'btn danger small' }),
          ),
        ]),
      )
    : h('div', { class: 'empty' }, 'No pending requests.')
  box.replaceChildren(h('h3', { class: 'panel-title' }, 'Pending requests'), list)
}
