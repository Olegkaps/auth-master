import { api, session } from '../api'
import { completeSignIn } from '../accounts'
import { navigate } from '../router'
import { button, card, h, toast } from '../ui'

// Landing page for one-time email login links: /#/magic?token=...
export function magicView(params: URLSearchParams): HTMLElement {
  const wrap = h('div', { class: 'auth-screen' })
  const box = card(null, h('h3', { class: 'panel-title' }, 'Signing you in…'), h('p', { class: 'muted small', 'data-testid': 'magic-status' }, 'Verifying your login link.'))
  wrap.append(h('div', { class: 'auth-brand' }, h('h1', {}, 'auth-master')), box)

  const token = (params.get('token') ?? '').trim()
  void (async () => {
    if (!token) {
      showError(box, 'Missing or invalid link.')
      return
    }
    try {
      const deviceId = session.deviceId
      const r = await api.magicLinkVerify(token, deviceId)
      await completeSignIn(r, deviceId)
      toast('Signed in via login link.', 'ok')
      navigate('/')
    } catch (e) {
      showError(box, e instanceof Error ? e.message : 'Link is invalid or expired.')
    }
  })()

  return wrap
}

function showError(box: HTMLElement, msg: string): void {
  box.replaceChildren(
    h('h3', { class: 'panel-title' }, 'Login link failed'),
    h('p', { class: 'msg err', 'data-testid': 'magic-status' }, msg),
    button('Back to sign in', () => navigate('/login'), 'secondary'),
  )
}
