import { api } from '../api'
import { button, card, field, h, run, textInput, toast } from '../ui'

export function invitesView(): HTMLElement {
  const email = textInput({ type: 'email', placeholder: 'optional — locks the invite to this email', 'data-testid': 'invite-email' })
  const ttl = textInput({ type: 'number', placeholder: '86400' })
  const superuser = h('input', { type: 'checkbox', 'data-testid': 'invite-superuser' }) as HTMLInputElement
  const result = h('div', { class: 'stack' })

  const create = card(
    'Create registration invite',
    h('p', { class: 'muted small' }, 'Superuser only. Generates a one-time token; share the link with the new user.'),
    field('Locked email', email),
    field('TTL seconds', ttl, 'Defaults to the server policy when empty'),
    h('label', { class: 'checkbox-row' }, superuser, h('span', {}, 'Grant superuser access on registration')),
    button('Generate invite', async () => {
      const secs = parseInt(ttl.value, 10)
      const r = await run(api.createInvite(email.value.trim(), Number.isFinite(secs) ? secs : 0, superuser.checked), 'Invite created.')
      if (!r) return
      renderResult(result, r)
    }, 'primary', { 'data-testid': 'invite-generate' }),
  )

  return h(
    'div',
    { class: 'page' },
    h('div', { class: 'page-head' }, h('h2', {}, 'Invites'), h('p', { class: 'muted' }, 'Onboard new users with time-limited registration links.')),
    create,
    result,
  )
}

function renderResult(host: HTMLElement, r: { token: string; expires_at: string; registration_url: string }): void {
  // Prefer an in-app link so the demo flow stays self-contained.
  const appLink = `${location.origin}/#/register?token=${encodeURIComponent(r.token)}`
  const tokenField = textInput({ value: r.token, readonly: 'true', 'data-testid': 'invite-token-field' })
  const linkField = textInput({ value: appLink, readonly: 'true', 'data-testid': 'invite-link-field' })
  host.replaceChildren(
    card(
      'Invite ready',
      field('Token', tokenField),
      field('Registration link (this demo)', linkField),
      h('p', { class: 'muted small' }, `Backend registration_url: ${r.registration_url} · expires ${r.expires_at}`),
      h(
        'div',
        { class: 'btn-row' },
        button('Copy link', () => {
          void navigator.clipboard?.writeText(appLink)
          toast('Link copied.', 'info')
        }),
        button('Open register page', () => {
          location.hash = `/register?token=${encodeURIComponent(r.token)}`
        }, 'secondary'),
      ),
    ),
  )
}
