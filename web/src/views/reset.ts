import { api } from '../api'
import { navigate } from '../router'
import { button, card, clear, field, h, run, textInput, toast } from '../ui'

export function resetView(params: URLSearchParams): HTMLElement {
  const wrap = h('div', { class: 'auth-screen' })
  const box = card(null)
  wrap.append(
    h('div', { class: 'auth-brand' }, h('h1', {}, 'Reset password'), h('p', { class: 'muted' }, 'For forgotten or expired passwords — no sign-in required.')),
    box,
    h('p', { class: 'auth-alt' }, 'Remembered it? ', h('a', { href: '#/login' }, 'Back to sign in')),
  )

  const step1 = (prefill = ''): void => {
    clear(box)
    const login = textInput({ placeholder: 'your login', value: prefill, autocomplete: 'username' })
    const submit = button('Email me a code', async () => {
      const l = login.value.trim()
      if (!l) {
        toast('Enter your login first.', 'err')
        return
      }
      // The backend always returns 200 (no account enumeration), so we advance
      // regardless and let the code step reveal whether it was valid.
      const r = await run(api.passwordResetStart(l))
      if (!r) return
      toast('If the account exists, a code was sent (check Mailpit at :8025).', 'info')
      step2(l)
    })
    login.addEventListener('keydown', (e) => e.key === 'Enter' && submit.click())
    box.append(
      h('h3', { class: 'panel-title' }, 'Request a reset code'),
      field('Login', login),
      submit,
    )
    login.focus()
  }

  const step2 = (login: string): void => {
    clear(box)
    const code = textInput({ inputmode: 'numeric', placeholder: '123456' })
    const pw = textInput({ type: 'password', autocomplete: 'new-password', placeholder: 'new password' })
    const submit = button('Set new password', async () => {
      const r = await run(api.passwordResetComplete(login, code.value.trim(), pw.value), 'Password reset — you can sign in now.')
      if (r === undefined) return
      navigate('/login')
    })
    pw.addEventListener('keydown', (e) => e.key === 'Enter' && submit.click())
    box.append(
      h('h3', { class: 'panel-title' }, 'Choose a new password'),
      h('p', { class: 'muted small' }, `Resetting the password for ${login}.`),
      field('Reset code', code),
      field('New password', pw),
      submit,
      button('← Use a different login', () => step1(login), 'ghost'),
    )
    code.focus()
  }

  step1(params.get('login') ?? '')
  return wrap
}
