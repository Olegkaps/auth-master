import { expect, type Browser, type Page } from '@playwright/test'

const MAILPIT = process.env.E2E_MAILPIT_URL || 'http://localhost:8025'

export const ADMIN = {
  login: process.env.E2E_ADMIN_LOGIN || 'admin',
  password: process.env.E2E_ADMIN_PASSWORD || 'Adm1n!Passw0rd123',
  email: process.env.E2E_ADMIN_EMAIL || 'admin@localhost',
}

async function mailFetch(path: string, init?: RequestInit): Promise<Response> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 3_000)
  try {
    return await fetch(`${MAILPIT}${path}`, { ...init, signal: controller.signal })
  } finally {
    clearTimeout(timer)
  }
}

/** Delete all messages so the next OTP is unambiguous (tests run serially). */
export async function clearMail(): Promise<void> {
	let lastError: unknown
	for (let attempt = 0; attempt < 3; attempt++) {
		try {
			const response = await mailFetch('/api/v1/messages', { method: 'DELETE' })
			if (response.ok) return
			lastError = new Error(`Mailpit delete returned ${response.status}`)
		} catch (error) {
			lastError = error
		}
		await new Promise((resolve) => setTimeout(resolve, 100))
	}
	throw lastError
}

interface MailMessage {
  ID: string
  Subject: string
  To: Array<{ Address: string }>
}

/** Poll Mailpit for the latest message to `email` and extract its 6-digit code. */
export async function waitForOtp(email: string, subjectIncludes = 'code'): Promise<string> {
  for (let i = 0; i < 40; i++) {
    const res = await mailFetch('/api/v1/messages?limit=30')
    if (res.ok) {
      const { messages } = (await res.json()) as { messages: MailMessage[] }
      const hit = messages.find(
        (m) => m.To.some((t) => t.Address.toLowerCase() === email.toLowerCase()) && m.Subject.toLowerCase().includes(subjectIncludes.toLowerCase()),
      )
      if (hit) {
        const full = await (await mailFetch(`/api/v1/message/${hit.ID}`)).json()
        const match = /(\d{6})/.exec(full.Text || '')
        if (match) return match[1]
      }
    }
    await new Promise((r) => setTimeout(r, 250))
  }
  throw new Error(`no OTP email for ${email} within timeout`)
}

/** Poll Mailpit for the newest magic-login link to `email` and return its token. */
export async function waitForMagicToken(email: string): Promise<string> {
  for (let i = 0; i < 40; i++) {
    const res = await mailFetch('/api/v1/messages?limit=30')
    if (res.ok) {
      const { messages } = (await res.json()) as { messages: MailMessage[] }
      const hit = messages.find((m) => m.To.some((t) => t.Address.toLowerCase() === email.toLowerCase()) && m.Subject.toLowerCase().includes('link'))
      if (hit) {
        const full = await (await mailFetch(`/api/v1/message/${hit.ID}`)).json()
        const match = /token=([A-Za-z0-9]+)/.exec(full.Text || '')
        if (match) return match[1]
      }
    }
    await new Promise((r) => setTimeout(r, 250))
  }
  throw new Error(`no magic-link email for ${email} within timeout`)
}

/** Two-step login on an already-visible login form (password → email OTP). */
export async function submitLogin(page: Page, login: string, password: string, email: string): Promise<void> {
  await clearMail()
  await page.getByTestId('login-input').fill(login)
  await page.getByTestId('password-input').fill(password)
  await page.getByTestId('continue-btn').click()
  const code = await waitForOtp(email)
  await page.getByTestId('otp-input').fill(code)
  await page.getByTestId('verify-btn').click()
  await expect(page.getByTestId('dashboard')).toBeVisible()
}

/** Full sign-in from scratch: navigate to the login screen, then submit. */
export async function signIn(page: Page, login: string, password: string, email: string): Promise<void> {
  await page.goto('/#/login')
  await submitLogin(page, login, password, email)
}

/** Navigate within the SPA via the sidebar without a full reload. */
export async function nav(page: Page, path: string): Promise<void> {
  await page.locator(`a[data-path="${path}"]`).click()
}

export function uniqueSuffix(): string {
  // Playwright forbids Date.now() nowhere; unique enough for a serial run.
  return `${Date.now().toString(36)}${Math.floor(Math.random() * 1e4)}`
}

/** As the signed-in admin, mint an invite and register a fresh user (separate context). */
export async function inviteAndRegister(adminPage: Page, browser: Browser, login: string, email: string, pass: string): Promise<void> {
  await nav(adminPage, '/admin/invites')
  await adminPage.getByTestId('invite-email').fill(email)
	const created = adminPage.waitForResponse((response) => response.url().includes('/v1/admin/registration-invites') && response.request().method() === 'POST')
  await adminPage.getByTestId('invite-generate').click()
	const response = await created
	expect(response.status()).toBe(201)
	const token = ((await response.json()) as { token: string }).token
  const ctx = await browser.newContext()
  const p = await ctx.newPage()
  await p.goto(`/#/register?token=${encodeURIComponent(token)}`)
  await p.getByTestId('reg-login').fill(login)
  await p.getByTestId('reg-email').fill(email)
  await p.getByTestId('reg-password').fill(pass)
  await p.getByTestId('reg-submit').click()
  await expect(p.getByTestId('login-input')).toBeVisible()
  await ctx.close()
}
