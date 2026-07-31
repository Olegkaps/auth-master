import { expect, test } from '@playwright/test'
import { ADMIN, clearMail, inviteAndRegister, nav, signIn, submitLogin, uniqueSuffix, waitForOtp } from './helpers'

// Password change is two-factor: current password + an emailed code.
test('password change requires 2FA', async ({ page, browser }) => {
  const sfx = uniqueSuffix()
  const login = `pw${sfx}`
  const email = `pw${sfx}@localhost`
  const pass = 'PwChange!-9a'
  const newPass = 'Zqx7!Rotated-Key'

  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await inviteAndRegister(page, browser, login, email, pass)

  const ctx = await browser.newContext()
  const up = await ctx.newPage()
  await signIn(up, login, pass, email)
  await nav(up, '/profile')

  await up.getByTestId('pw-old').fill(pass)
  await up.getByTestId('pw-new').fill(newPass)
  // Without the 2FA code the change is rejected.
  await up.getByTestId('pw-submit').click()
  await expect(up.getByText(/invalid 2fa code/i)).toBeVisible()

  // Request the code, read it from email, and complete the change.
  await clearMail()
  await up.getByTestId('pw-2fa-start').click()
  const code = await waitForOtp(email, 'password')
  await up.getByTestId('pw-old').fill(pass)
  await up.getByTestId('pw-new').fill(newPass)
  await up.getByTestId('pw-code').fill(code)
  await up.getByTestId('pw-submit').click()
  await expect(up.getByText(/Password updated/i)).toBeVisible()
  await ctx.close()
})

// A standalone step-up 2FA challenge (started from the profile, not login/password
// change) can be started and verified, and its status reads "verified".
test('standalone step-up 2FA can be started and verified', async ({ page }) => {
  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await nav(page, '/profile')

  await clearMail()
  await page.getByTestId('stepup-start').click()
  await expect(page.getByTestId('stepup-corr')).not.toHaveValue('')
  const code = await waitForOtp(ADMIN.email, 'step-up')
  await page.getByTestId('stepup-code').fill(code)
  await page.getByTestId('stepup-complete').click()
  await expect(page.getByTestId('stepup-status')).toContainText(/verified/i)

  // The API status endpoint confirms the challenge is resolved (approved).
  await page.getByTestId('stepup-status-btn').click()
  await expect(page.getByTestId('stepup-status')).toContainText(/approved/i)
})

// Opening an invite link while already signed in lets you register and add the
// new account without signing out of the current one.
test('can open an invite link while signed in and add the account', async ({ page }) => {
  const sfx = uniqueSuffix()
  const login = `inv${sfx}`
  const email = `inv${sfx}@localhost`
  const pass = 'InviteWhileIn-9a'

  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)

  // Mint an invite as admin, then open the register link WHILE still signed in.
  await nav(page, '/admin/invites')
  await page.getByTestId('invite-email').fill(email)
  await page.getByTestId('invite-generate').click()
  const token = await page.getByTestId('invite-token-field').inputValue()

  await page.goto(`/#/register?token=${encodeURIComponent(token)}`)
  await expect(page.getByTestId('reg-login')).toBeVisible() // not bounced to the dashboard
  await page.getByTestId('reg-login').fill(login)
  await page.getByTestId('reg-email').fill(email)
  await page.getByTestId('reg-password').fill(pass)
  await page.getByTestId('reg-submit').click()

  // Lands on add-account login (prefilled); finish signing into the new account.
  await expect(page.getByTestId('login-input')).toHaveValue(login)
  await submitLogin(page, login, pass, email)
  await expect(page.getByTestId('welcome')).toContainText(login)

  // Both accounts are now in the switcher.
  await page.getByTestId('account-chip').click()
  await expect(page.getByTestId(`account-${ADMIN.login}`)).toBeVisible()
  await expect(page.getByTestId(`account-${login}`)).toBeVisible()
})

// After the access token expires, an action transparently refreshes it and the
// user stays signed in (needs a short ACCESS_TOKEN_TTL on the backend to be
// meaningful — see e2e/README.md). Safe (passes) with the default TTL too.
test('stays signed in after the access token expires', async ({ page }) => {
  test.setTimeout(60_000)
  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  const ttl = Number(process.env.E2E_ACCESS_TTL_SEC ?? 20)
  await page.waitForTimeout(ttl * 1000 + 2000) // idle past the access-token TTL
  await nav(page, '/roles')
  await expect(page.getByTestId('roles-page')).toBeVisible() // auto-refresh kept us in
  await nav(page, '/')
  await expect(page.getByTestId('dashboard')).toBeVisible()
})

// A wrong OTP burns the challenge — the UI drops back to the password step and a
// fresh sign-in works (no second OTP attempt on the same code).
test('wrong OTP forces re-entering the password', async ({ page }) => {
  await clearMail()
  await page.goto('/#/login')
  await page.getByTestId('login-input').fill(ADMIN.login)
  await page.getByTestId('password-input').fill(ADMIN.password)
  await page.getByTestId('continue-btn').click()

  const code = await waitForOtp(ADMIN.email)
  const wrong = code === '000000' ? '111111' : '000000'
  await page.getByTestId('otp-input').fill(wrong)
  await page.getByTestId('verify-btn').click()

  // Back on the password step (the OTP field is gone).
  await expect(page.getByTestId('login-input')).toBeVisible()
  await expect(page.getByTestId('otp-input')).toHaveCount(0)

  // A fresh full sign-in succeeds.
  await submitLogin(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await expect(page.getByTestId('dashboard')).toBeVisible()
})

// A superuser invite produces a superuser account (admin nav becomes visible).
test('superuser invite grants admin access', async ({ page, browser }) => {
  const sfx = uniqueSuffix()
  const login = `super${sfx}`
  const email = `super${sfx}@localhost`
  const pass = 'Super!Invite-9a'

  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await nav(page, '/admin/invites')
  await page.getByTestId('invite-email').fill(email)
  await page.getByTestId('invite-superuser').check()
  await page.getByTestId('invite-generate').click()
  const token = await page.getByTestId('invite-token-field').inputValue()

  const ctx = await browser.newContext()
  const up = await ctx.newPage()
  await up.goto(`/#/register?token=${encodeURIComponent(token)}`)
  await expect(up.getByText(/grants superuser/i)).toBeVisible()
  await up.getByTestId('reg-login').fill(login)
  await up.getByTestId('reg-email').fill(email)
  await up.getByTestId('reg-password').fill(pass)
  await up.getByTestId('reg-submit').click()
  await expect(up.getByTestId('login-input')).toBeVisible()

  await signIn(up, login, pass, email)
  // The new account is a superuser → admin navigation is present.
  await expect(up.locator('a[data-path="/admin/users"]')).toBeVisible()
  await ctx.close()
})

// Revoking a session is a single click — no "email me a code" step.
test('one-click session revoke (no OTP)', async ({ page }) => {
  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await nav(page, '/sessions')

  const revokeBtns = page.locator('[data-testid^="revoke-session-"]')
  await expect(revokeBtns.first()).toBeVisible() // wait for the async table to load
  const before = await revokeBtns.count()
  expect(before).toBeGreaterThan(0)
  await revokeBtns.first().click()
  // One click, no OTP: a success toast and the revoked row loses its button.
  await expect(page.getByText(/Session revoked/i)).toBeVisible()
  await expect(revokeBtns).toHaveCount(before - 1)
})
