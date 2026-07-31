import { api, session } from '../api'
import { button, card, field, h, modal, run, textInput } from '../ui'

export function securityView(): HTMLElement {
  return h(
    'div',
    { class: 'page' },
    h('div', { class: 'page-head' }, h('h2', {}, 'Security & keys'), h('p', { class: 'muted' }, 'Superuser operations on the signing key and token introspection.')),
    h('div', { class: 'grid-2' }, rotateCard(), introspectCard()),
  )
}

function rotateCard(): HTMLElement {
  return card(
    'Signing key rotation',
    h('p', { class: 'muted small' }, 'Rotates the JWT signing key. Existing access tokens become stale and clients transparently refresh.'),
    button('Rotate signing key', () => {
      const body = h('p', {}, 'This invalidates current access tokens (they auto-refresh). Continue?')
      const close = modal('Rotate signing key', body, [
        button('Cancel', () => close(), 'ghost'),
        button('Rotate', async () => {
          await run(api.rotateSigningKey(), 'Signing key rotated.')
          close()
        }, 'danger'),
      ])
    }, 'danger'),
  )
}

function introspectCard(): HTMLElement {
  const tok = textInput({ placeholder: 'paste a JWT (blank = your access token)' })
  const out = h('pre', { class: 'code-out' }, '—')
  return card(
    'Token introspection',
    h('p', { class: 'muted small' }, 'Inspect any access or service JWT via /v1/auth/token/info.'),
    field('Bearer token', tok),
    button('Introspect', async () => {
      const r = await run(api.tokenInfo(tok.value.trim() || session.accessToken))
      out.textContent = r ? JSON.stringify(r, null, 2) : 'failed'
    }, 'secondary'),
    out,
  )
}
