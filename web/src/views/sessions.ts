import { api, session, type Session } from '../api'
import { badge, button, card, h, run, shortId, table } from '../ui'

export async function sessionsView(): Promise<HTMLElement> {
  const page = h('div', { class: 'page' })
  const reload = async (): Promise<void> => render(page, await api.listSessions(), reload)
  await reload()
  return page
}

function fmtTime(v: string): string {
  if (!v || v.startsWith('0001')) return '—'
  const t = Date.parse(v)
  return Number.isFinite(t) ? new Date(t).toLocaleString() : v
}

function render(page: HTMLElement, sessions: Session[], reload: () => Promise<void>): void {
  const rows = sessions.map((s) => {
    const here = s.deviceId === session.deviceId
    return [
      shortId(s.id),
      h('span', {}, `${(s.deviceId ?? '').slice(0, 18)}${s.deviceLabel ? ` · ${s.deviceLabel.slice(0, 30)}` : ''}`, here ? badge('this device', 'yellow') : null),
      fmtTime(s.createdAt),
      fmtTime(s.expiresAt),
      s.revoked ? badge('revoked', 'red') : badge('active', 'green'),
      s.revoked
        ? h('span', { class: 'muted small' }, '—')
        : button('Revoke', () => revoke(s, reload), 'danger', { class: 'btn danger small', 'data-testid': `revoke-session-${s.deviceId}` }),
    ]
  })

  page.replaceChildren(
    h(
      'div',
      { class: 'page-head row-between' },
      h('div', {}, h('h2', {}, 'Sessions'), h('p', { class: 'muted' }, 'Refresh sessions bound to your devices. Revoke any with one click.')),
      button('Reload', () => reload(), 'secondary'),
    ),
    card(null, table(['ID', 'Device', 'Created', 'Expires', 'Status', ''], rows)),
  )
}

// One-click revoke — no email OTP: you're already authenticated.
async function revoke(s: Session, reload: () => Promise<void>): Promise<void> {
  const r = await run(api.revokeSession(s.id), 'Session revoked.')
  if (r !== undefined) await reload()
}
