import { api, isSignedIn } from '../api'
import { navigate } from '../router'
import { badge, button, card, field, h, run, textInput, toast } from '../ui'

export function registerView(params: URLSearchParams): HTMLElement {
  const signedIn = isSignedIn()
  const wrap = h('div', { class: 'auth-screen' })
  const box = card(null)
  wrap.append(
    h(
      'div',
      { class: 'auth-brand' },
      h('h1', {}, 'Create account'),
      h('p', { class: 'muted' }, signedIn ? 'Register another account — you stay signed in to the current one.' : 'Registration is invite-only.'),
    ),
    box,
    signedIn
      ? h('p', { class: 'auth-alt' }, h('a', { href: '#/' }, '← Back to app'))
      : h('p', { class: 'auth-alt' }, 'Already registered? ', h('a', { href: '#/login' }, 'Sign in')),
  )

  const token = textInput({ placeholder: 'invite token', value: params.get('token') ?? '', 'data-testid': 'reg-token' })
  const login = textInput({ autocomplete: 'username', 'data-testid': 'reg-login' })
  const email = textInput({ type: 'email', 'data-testid': 'reg-email' })
  const password = textInput({ type: 'password', autocomplete: 'new-password', 'data-testid': 'reg-password' })
  const status = h('div', { class: 'inline-status' })

  const checkInvite = async (): Promise<void> => {
    status.replaceChildren()
    const t = token.value.trim()
    if (!t) return
    const r = await run(api.previewInvite(t))
    if (!r) return
    if (r.valid) {
      status.append(badge('invite valid', 'green'), h('span', { class: 'muted small' }, r.email ? ` locked to ${r.email} · expires ${r.expires_at}` : ` any email · expires ${r.expires_at}`))
      if (r.superuser) status.append(badge('grants superuser', 'yellow'))
      if (r.email) email.value = r.email
    } else {
      status.append(badge('invalid or expired', 'red'))
    }
  }
  token.addEventListener('blur', checkInvite)

  const submit = button('Register', async () => {
    const r = await run(
      api.register(token.value.trim(), login.value.trim(), email.value.trim(), password.value),
      'Account created. You can sign in now.',
    )
    if (!r) return
    toast(`user_id: ${r.user_id}`, 'info')
    // If already signed in, go to add-account login so the new account joins the
    // switcher without signing out of the current one.
    navigate(signedIn ? `/login?add=1&login=${encodeURIComponent(login.value.trim())}` : '/login')
  }, 'primary', { 'data-testid': 'reg-submit' })

  box.append(
    h('h3', { class: 'panel-title' }, 'Registration'),
    field('Invite token', token, 'From an admin-issued registration invite'),
    status,
    field('Login', login),
    field('Email', email),
    field('Password', password),
    submit,
  )
  if (token.value.trim()) void checkInvite()
  return wrap
}
