import { api, session } from '../api'
import { accounts, activeAccountId, completeSignIn, switchTo } from '../accounts'
import { navigate } from '../router'
import { avatar, button, card, clear, field, h, run, textInput, toast } from '../ui'

export function loginView(params?: URLSearchParams): HTMLElement {
  const addMode = params?.get('add') === '1'
  const wrap = h('div', { class: 'auth-screen' })
  const box = card(null)
  const brand = h(
    'div',
    { class: 'auth-brand' },
    h('h1', {}, addMode ? 'Add account' : 'auth-master'),
    h('p', { class: 'muted' }, addMode ? 'Sign in to another account without signing out of the current one.' : 'Demo application built on the auth REST API'),
  )
  const alt = addMode
    ? h('p', { class: 'auth-alt' }, h('a', { href: '#/' }, '← Back to app'))
    : h('p', { class: 'auth-alt' }, 'Need an account? ', h('a', { href: '#/register' }, 'Register'))
  const accts = existingAccounts()
  wrap.append(brand, ...(accts ? [accts] : []), box, alt)

  const resetLink = (login: string): HTMLElement =>
    h('a', { href: `#/reset${login ? `?login=${encodeURIComponent(login)}` : ''}` }, 'Forgot password?')

  // Quick-switch into any already-signed-in account without re-entering credentials.
  function existingAccounts(): HTMLElement | null {
    const list = accounts().filter((a) => a.id !== activeAccountId())
    if (list.length === 0) return null
    return h(
      'div',
      { class: 'auth-accounts', 'data-testid': 'login-accounts' },
      h('p', { class: 'muted small' }, 'Continue as'),
      ...list.map((a) =>
        h(
          'button',
          {
            type: 'button',
            class: 'account-pick card-like',
            'data-testid': `login-switch-${a.login}`,
            onclick: async () => {
              await run(switchTo(a.id))
              navigate('/')
            },
          },
          avatar(a.login, 'sm'),
          h('div', { class: 'user-meta' }, h('strong', {}, a.login), h('span', { class: 'muted small' }, a.superuser ? 'superuser' : a.kind)),
        ),
      ),
    )
  }

  const step1 = (prefillLogin = params?.get('login') ?? ''): void => {
    clear(box)
    const login = textInput({ placeholder: 'admin', autocomplete: 'username', value: prefillLogin, 'data-testid': 'login-input' })
    const password = textInput({ type: 'password', autocomplete: 'current-password', 'data-testid': 'password-input' })
    const submit = button('Continue', async () => {
      const r = await run(api.login(login.value.trim(), password.value), undefined)
      if (!r) return
      if (r.password_expired) {
        toast('Password expired — reset it to continue.', 'err')
        navigate(`/reset?login=${encodeURIComponent(login.value.trim())}`)
        return
      }
      if (r.otp_sent === false) {
        const deviceId = session.deviceId
        try {
          const verified = await api.verifyOtp(r.login_challenge ?? '', '', deviceId)
          await completeSignIn(verified, deviceId)
          toast('Signed in.', 'ok')
          navigate('/')
        } catch {
          // The server challenge is intentionally single-use. If automatic
          // continuation fails, restart cleanly instead of exposing an OTP form
          // that can never succeed for an empty-code challenge.
          step1(login.value.trim())
          toast('Automatic sign-in could not be completed. Re-enter your password to try again.', 'err')
        }
        return
      }
      toast('Code sent to your email (check Mailpit at :8025).', 'info')
      step2(login.value.trim(), r.login_challenge ?? '')
    })
    const magic = button('Email me a login link instead', async () => {
      const l = login.value.trim()
      if (!l) {
        toast('Enter your login first.', 'err')
        return
      }
      await run(api.magicLinkStart(l))
      toast('If the account exists, a sign-in link was requested. If it does not arrive, wait briefly and request another link.', 'info')
    }, 'ghost')
    login.addEventListener('keydown', (e) => e.key === 'Enter' && password.focus())
    password.addEventListener('keydown', (e) => e.key === 'Enter' && submit.click())
    box.append(
      h('h3', { class: 'panel-title' }, 'Sign in'),
      h(
        'p',
        { class: 'muted small', 'data-testid': 'login-alternatives' },
        'Use your password to continue. Depending on server policy, you may then be asked for an email code. Or request an email login link instead; magic links do not require a password.',
      ),
      field('Login', login),
      field('Password', password),
      submit,
      h('p', { class: 'auth-sub' }, resetLink(login.value.trim())),
      h('div', { class: 'auth-divider' }, 'or'),
      magic,
    )
    submit.dataset.testid = 'continue-btn'
    magic.dataset.testid = 'magic-link-btn'
    login.focus()
  }

  const step2 = (login: string, challenge: string): void => {
    clear(box)
    const code = textInput({ inputmode: 'numeric', placeholder: '123456', 'data-testid': 'otp-input' })
    const submit = button('Verify & sign in', async () => {
      // Stable per-browser device id: re-logging into the same account replaces
      // its session server-side (only the last stays active).
      const deviceId = session.deviceId
      const r = await run(api.verifyOtp(challenge, code.value.trim(), deviceId), 'Signed in.')
      if (!r) {
        // A wrong/expired code burns the challenge on the server — restart from
        // the password step (there is no second OTP attempt).
        toast('Please sign in again.', 'info')
        step1()
        return
      }
      await completeSignIn(r, deviceId)
      navigate('/')
    })
    code.addEventListener('keydown', (e) => e.key === 'Enter' && submit.click())
    box.append(
      h('h3', { class: 'panel-title' }, 'Enter the email code'),
      h('p', { class: 'muted small' }, `Signing in as ${login}. The code is tied to this attempt — it's useless without it.`),
      field('One-time code', code),
      submit,
      button('← Back', () => step1(login), 'ghost'),
    )
    submit.dataset.testid = 'verify-btn'
    code.focus()
  }

  step1()
  return wrap
}
