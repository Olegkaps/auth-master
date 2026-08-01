import { api, session } from '../api'
import { badge, button, card, field, h, run, table, textInput, toast } from '../ui'

export function profileView(): HTMLElement {
  const u = session.user!

  const details = card(
    'Profile',
    table(
      ['Field', 'Value'],
      [
        ['Login', h('strong', {}, u.login)],
        ['User ID', h('code', { class: 'mono' }, u.id)],
        ['Email', u.email ?? '—'],
        ['Kind', u.kind],
        ['Access', u.superuser ? badge('superuser', 'yellow') : badge('standard', 'gray')],
      ],
    ),
  )

  const oldPw = textInput({ type: 'password', autocomplete: 'current-password', 'data-testid': 'pw-old' })
  const newPw = textInput({ type: 'password', autocomplete: 'new-password', 'data-testid': 'pw-new' })
  const code = textInput({ inputmode: 'numeric', placeholder: '123456', 'data-testid': 'pw-code' })
  const password = card(
    'Change password',
    h('p', { class: 'muted small' }, 'Requires two-factor: your current password plus an emailed code.'),
    field('Current password', oldPw),
    field('New password', newPw),
    button('Email me a 2FA code', async () => {
      await run(api.changePassword2FAStart(), 'Code sent (check Mailpit at :8025).')
    }, 'secondary', { 'data-testid': 'pw-2fa-start' }),
    field('2FA code', code),
    button('Update password', async () => {
      const r = await run(api.changePassword(oldPw.value, newPw.value, code.value.trim()), 'Password updated.')
      if (r !== undefined) {
        oldPw.value = ''
        newPw.value = ''
        code.value = ''
      }
    }, 'primary', { 'data-testid': 'pw-submit' }),
  )

  return h(
    'div',
    { class: 'page' },
    h('div', { class: 'page-head' }, h('h2', {}, 'Profile & security')),
    h('div', { class: 'grid-2' }, details, hasRoleCard()),
    password,
    stepUpCard(),
  )
}

// Checks GET /v1/me/has-role — true if you hold the role directly or via the
// hierarchy (membership in an ancestor role grants descendant roles).
function hasRoleCard(): HTMLElement {
  const name = textInput({ placeholder: 'editors', 'data-testid': 'hasrole-input' })
  const result = h('span', { class: 'muted small', 'data-testid': 'hasrole-result' }, '—')
  const check = async (): Promise<void> => {
    const r = await run(api.hasRole(name.value.trim()))
    if (!r) return
    result.replaceChildren(r.has_role ? badge('has role', 'green') : badge('no', 'gray'))
  }
  name.addEventListener('keydown', (e) => e.key === 'Enter' && void check())
  return card(
    'Check role access (has-role)',
    h('p', { class: 'muted small' }, 'Resolves through the role hierarchy — a parent-role membership grants child roles.'),
    field('Role name', name),
    h('div', { class: 'inline-status' }, button('Check', check, 'secondary', { 'data-testid': 'hasrole-btn' }), result),
  )
}

// Step-up 2FA demo: start a challenge, poll status, complete with the emailed code.
function stepUpCard(): HTMLElement {
  const corr = textInput({ placeholder: 'correlation id appears here', 'data-testid': 'stepup-corr' })
  const code = textInput({ inputmode: 'numeric', placeholder: '123456', 'data-testid': 'stepup-code' })
  const statusEl = h('span', { class: 'muted small', 'data-testid': 'stepup-status' }, 'idle')

  return card(
    'Step-up 2FA (elevated action demo)',
    h('p', { class: 'muted small' }, 'Simulates re-verifying identity before a sensitive action: start → receive OTP by email → complete.'),
    h(
      'div',
      { class: 'btn-row' },
      button('Start challenge', async () => {
        const r = await run(api.stepUpStart(300), 'Challenge started — code emailed.')
        if (r) corr.value = r.correlation_id
      }, 'primary', { 'data-testid': 'stepup-start' }),
      button('Check status', async () => {
        const r = await run(api.stepUpStatus(corr.value.trim()))
        if (r) statusEl.replaceChildren(badge(r.status, r.status === 'verified' ? 'green' : 'yellow'))
      }, 'secondary', { 'data-testid': 'stepup-status-btn' }),
      button('Expire', async () => {
        await run(api.stepUpExpire(corr.value.trim()), 'Challenge expired.')
        statusEl.textContent = 'expired'
      }, 'ghost'),
    ),
    field('Correlation id', corr),
    field('OTP code', code),
    h('div', { class: 'inline-status' }, h('span', { class: 'muted small' }, 'Status: '), statusEl),
    button('Complete', async () => {
      const r = await run(api.stepUpComplete(corr.value.trim(), code.value.trim()), 'Step-up verified.')
      if (r) {
        statusEl.replaceChildren(badge('verified', 'green'))
        toast('You could now perform the elevated action.', 'info')
      }
    }, 'primary', { 'data-testid': 'stepup-complete' }),
  )
}
