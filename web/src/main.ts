import './style.css'

const API = ''

let accessToken = ''
let csrfToken = ''
let deviceId = localStorage.getItem('device_id') || crypto.randomUUID()
localStorage.setItem('device_id', deviceId)

function el(html: string): HTMLElement {
  const t = document.createElement('template')
  t.innerHTML = html.trim()
  return t.content.firstElementChild as HTMLElement
}

async function api(
  path: string,
  opts: RequestInit & { skipAuth?: boolean } = {},
): Promise<Response> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(opts.headers as Record<string, string>),
  }
  if (!opts.skipAuth && accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`
  }
  if (csrfToken && (opts.method === 'POST' || opts.method === 'DELETE')) {
    headers['X-CSRF-Token'] = csrfToken
  }
  let res = await fetch(`${API}${path}`, { ...opts, headers, credentials: 'include' })
  if (res.headers.get('X-Token-Stale') === '1' && accessToken) {
    const r2 = await fetch(`${API}/v1/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({ device_id: deviceId }),
    })
    if (r2.ok) {
      const j = await r2.json()
      accessToken = (j as { access_token: string }).access_token
      headers['Authorization'] = `Bearer ${accessToken}`
      res = await fetch(`${API}${path}`, { ...opts, headers, credentials: 'include' })
    }
  }
  return res
}

function render() {
  const root = document.querySelector<HTMLDivElement>('#app')!
  root.innerHTML = ''
  root.appendChild(el(`<h1>Auth</h1>`))

  const login = el(`
    <div>
      <h2>Sign in</h2>
      <label>Login <input type="text" id="login" autocomplete="username" /></label>
      <label>Password <input type="password" id="password" autocomplete="current-password" /></label>
      <button type="button" id="btn-login">Send email code</button>
      <div class="msg" id="login-msg"></div>
    </div>
  `)
  root.appendChild(login)

  const otp = el(`
    <div>
      <h2>Email OTP</h2>
      <label>Code <input type="text" id="otp" inputmode="numeric" /></label>
      <button type="button" id="btn-verify">Verify & sign in</button>
      <div class="msg" id="otp-msg"></div>
    </div>
  `)
  root.appendChild(otp)

  const sess = el(`
    <section>
      <h2>Sessions</h2>
      <button type="button" class="secondary" id="btn-sessions">Refresh list</button>
      <button type="button" class="secondary" id="btn-revoke-otp">Email OTP for revoke</button>
      <ul class="sessions" id="session-list"></ul>
      <div class="msg" id="sess-msg"></div>
      <label>Revoke OTP <input type="text" id="revoke-otp" inputmode="numeric" /></label>
    </section>
  `)
  root.appendChild(sess)

  const loginMsg = login.querySelector('#login-msg')!
  login.querySelector('#btn-login')!.addEventListener('click', async () => {
    loginMsg.textContent = ''
    const l = (login.querySelector('#login') as HTMLInputElement).value
    const p = (login.querySelector('#password') as HTMLInputElement).value
    const res = await api('/v1/auth/login', {
      method: 'POST',
      skipAuth: true,
      body: JSON.stringify({ login: l, password: p }),
    })
    const j = await res.json().catch(() => ({}))
    if (!res.ok) {
      loginMsg.textContent = (j as { error?: string }).error || res.statusText
      loginMsg.classList.add('err')
      return
    }
    if ((j as { password_expired?: boolean }).password_expired) {
      loginMsg.textContent = 'Password expired — change via API'
      loginMsg.classList.add('err')
      return
    }
    loginMsg.textContent = 'Check your email for the code.'
    loginMsg.classList.remove('err')
  })

  const otpMsg = otp.querySelector('#otp-msg')!
  otp.querySelector('#btn-verify')!.addEventListener('click', async () => {
    otpMsg.textContent = ''
    const l = (login.querySelector('#login') as HTMLInputElement).value
    const code = (otp.querySelector('#otp') as HTMLInputElement).value
    const res = await api('/v1/auth/login/verify-otp', {
      method: 'POST',
      skipAuth: true,
      body: JSON.stringify({
        login: l,
        code,
        device_id: deviceId,
        device_label: navigator.userAgent.slice(0, 80),
      }),
    })
    const j = await res.json().catch(() => ({}))
    if (!res.ok) {
      otpMsg.textContent = (j as { error?: string }).error || res.statusText
      otpMsg.classList.add('err')
      return
    }
    accessToken = (j as { access_token: string; csrf_token: string }).access_token
    csrfToken = (j as { csrf_token: string }).csrf_token
    otpMsg.textContent = 'Signed in.'
    otpMsg.classList.remove('err')
    loadSessions()
  })

  const sessMsg = sess.querySelector('#sess-msg')!
  async function loadSessions() {
    const list = sess.querySelector('#session-list')!
    list.innerHTML = ''
    if (!accessToken) {
      sessMsg.textContent = 'Sign in first.'
      return
    }
    const res = await api('/v1/sessions')
    const j = await res.json().catch(() => ({}))
    if (!res.ok) {
      sessMsg.textContent = (j as { error?: string }).error || res.statusText
      return
    }
    sessMsg.textContent = ''
    for (const s of (j as { sessions: { id: string; device_id: string; revoked: boolean }[] }).sessions) {
      const li = el(
        `<li><span><code>${s.id.slice(0, 8)}</code> ${s.device_id.slice(0, 12)}… ${s.revoked ? '(revoked)' : ''}</span></li>`,
      )
      if (!s.revoked) {
        const b = el(`<button type="button" class="secondary">Revoke</button>`) as HTMLButtonElement
        b.onclick = async () => {
          const otpVal = (sess.querySelector('#revoke-otp') as HTMLInputElement).value.trim()
          if (!otpVal) {
            sessMsg.textContent = 'Enter OTP from email first.'
            return
          }
          const r2 = await api(`/v1/sessions/${s.id}/revoke`, {
            method: 'POST',
            body: JSON.stringify({ code: otpVal }),
          })
          if (!r2.ok) {
            const e = await r2.json().catch(() => ({}))
            sessMsg.textContent = (e as { error?: string }).error || 'revoke failed'
            return
          }
          sessMsg.textContent = 'Revoked.'
          loadSessions()
        }
        li.appendChild(b)
      }
      list.appendChild(li)
    }
  }

  sess.querySelector('#btn-revoke-otp')!.addEventListener('click', async () => {
    sessMsg.textContent = ''
    const res = await api('/v1/sessions/revoke-otp', { method: 'POST', body: '{}' })
    if (!res.ok) {
      const e = await res.json().catch(() => ({}))
      sessMsg.textContent = (e as { error?: string }).error || 'failed'
      return
    }
    sessMsg.textContent = 'Check email for revoke code.'
  })

  sess.querySelector('#btn-sessions')!.addEventListener('click', () => loadSessions())
}

render()
