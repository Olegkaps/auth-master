import { api, isSignedIn } from '../api'
import { navigate } from '../router'
import { badge, button, card, field, h, run, textInput, toast } from '../ui'

export function registerView(params: URLSearchParams): HTMLElement {
  const signedIn = isSignedIn()
  const wrap = h('div', { class: 'auth-screen' })
  const box = card(null)
  const policyCopy = h(
    'p',
    { class: 'muted', 'data-testid': 'registration-policy' },
    signedIn ? 'Register another account — you stay signed in to the current one.' : 'Checking registration availability…',
  )
  wrap.append(
    h('div', { class: 'auth-brand' }, h('h1', {}, 'Create account'), policyCopy),
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
  const tokenField = field('Invite token', token, 'From an admin-issued registration invite')

  const submit = button(
    'Register',
    async () => {
      const r = await run(
        api.register(token.value.trim(), login.value.trim(), email.value.trim(), password.value),
        'Account created. You can sign in now.',
      )
      if (!r) return
      toast(`user_id: ${r.user_id}`, 'info')
      // If already signed in, go to add-account login so the new account joins the
      // switcher without signing out of the current one.
      navigate(signedIn ? `/login?add=1&login=${encodeURIComponent(login.value.trim())}` : '/login')
    },
    'primary',
    { 'data-testid': 'reg-submit', disabled: true },
  )

  let previewSequence = 0
  const checkInvite = async (): Promise<void> => {
    const sequence = ++previewSequence
    submit.disabled = true
    status.replaceChildren()
    const inviteToken = token.value.trim()
    const preview = await run(api.previewInvite(inviteToken))
    if (sequence !== previewSequence) return
    if (!preview) {
      policyCopy.textContent = 'Registration availability could not be loaded. Retry by leaving the invite field.'
      email.readOnly = false
      return
    }

    policyCopy.textContent = signedIn
      ? 'Register another account — you stay signed in to the current one.'
      : preview.registration_open
        ? 'Registration is open.'
        : 'Registration requires an invite.'
    tokenField.style.display = preview.registration_open && !inviteToken ? 'none' : ''
    email.readOnly = Boolean(preview.valid && preview.email)

    if (!inviteToken) {
      if (preview.registration_open) status.append(badge('open registration', 'green'))
      submit.disabled = false
      return
    }
    if (preview.valid) {
      status.append(
        badge('invite valid', 'green'),
        h(
          'span',
          { class: 'muted small' },
          preview.email ? ` locked to ${preview.email} · expires ${preview.expires_at}` : ` any email · expires ${preview.expires_at}`,
        ),
      )
      if (preview.superuser) status.append(badge('grants superuser', 'yellow'))
      if (preview.email) email.value = preview.email
    } else {
      status.append(badge('invalid or expired', 'red'))
      if (preview.registration_open) {
        status.append(
          button(
            'Discard invite and register openly',
            () => {
              token.value = ''
              email.readOnly = false
              window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}#/register`)
              void checkInvite()
            },
            'secondary',
            { 'data-testid': 'discard-invite' },
          ),
        )
      }
    }
    submit.disabled = false
  }

  token.addEventListener('input', () => {
    // Immediately invalidate any preview already in flight. Its late response
    // must not lock the email or enable submit for a different token.
    previewSequence++
    submit.disabled = true
    email.readOnly = false
    status.replaceChildren()
    policyCopy.textContent = 'Checking registration availability…'
  })
  token.addEventListener('blur', () => void checkInvite())

  box.append(
    h('h3', { class: 'panel-title' }, 'Registration'),
    tokenField,
    status,
    field('Login', login),
    field('Email', email),
    field('Password', password),
    submit,
  )
  void checkInvite()
  return wrap
}
