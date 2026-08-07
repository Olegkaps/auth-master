import { expect, test } from '@playwright/test'
import { ADMIN, clearMail, nav, signIn, submitLogin, uniqueSuffix, waitForMagicToken, waitForOtp } from './helpers'

test('passwordless login via one-time email link', async ({ page }) => {
  await clearMail()
  await page.goto('/#/login')
  await page.getByTestId('login-input').fill(ADMIN.login)
  await page.getByTestId('magic-link-btn').click()
  const token = await waitForMagicToken(ADMIN.email)
  await page.goto(`/#/magic?token=${encodeURIComponent(token)}`)
  await expect(page.getByTestId('dashboard')).toBeVisible()
  await expect(page.getByTestId('welcome')).toContainText(ADMIN.login)

  // The link is single-use — visiting it again fails.
  await page.goto(`/#/magic?token=${encodeURIComponent(token)}`)
  await expect(page.getByTestId('magic-status')).toContainText(/invalid|expired|failed/i)
})

test('admin signs in and sees the admin dashboard', async ({ page }) => {
  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await expect(page.getByTestId('welcome')).toContainText(ADMIN.login)
  // Admin-only nav is present for a superuser.
  await expect(page.locator('a[data-path="/admin/users"]')).toBeVisible()
})

test('full RBAC lifecycle: create role, invite, register, request, approve', async ({ page, browser }) => {
  const sfx = uniqueSuffix()
  const roleName = `e2e-role-${sfx}`
  const userLogin = `e2euser${sfx}`
  const userEmail = `e2euser${sfx}@localhost`
  const userPass = 'E2e!User-Pass9'

  // --- Admin: sign in and create a role ---------------------------------
  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await nav(page, '/roles')
  await page.getByTestId('create-role-btn').click()
  await page.getByTestId('role-name-input').fill(roleName)
  await page.getByTestId('role-desc-input').fill('created by e2e')
  await page.getByTestId('role-create-submit').click()
  await expect(page.getByRole('cell', { name: roleName, exact: true })).toBeVisible()

  // --- Admin: mint a registration invite --------------------------------
  await nav(page, '/admin/invites')
  await page.getByTestId('invite-email').fill(userEmail)
  await page.getByTestId('invite-generate').click()
  const token = await page.getByTestId('invite-token-field').inputValue()
  expect(token).not.toEqual('')

  // --- New user (separate browser context): register via the invite -----
  const userCtx = await browser.newContext()
  const userPage = await userCtx.newPage()
  await userPage.goto(`/#/register?token=${encodeURIComponent(token)}`)
  await userPage.getByTestId('reg-login').fill(userLogin)
  await userPage.getByTestId('reg-email').fill(userEmail)
  await userPage.getByTestId('reg-password').fill(userPass)
  await userPage.getByTestId('reg-submit').click()
  await expect(userPage.getByTestId('login-input')).toBeVisible() // redirected to login

  // --- New user: sign in and request the role ---------------------------
  await signIn(userPage, userLogin, userPass, userEmail)
  await nav(userPage, '/roles')
  await userPage.getByTestId(`request-${roleName}`).click()
  await expect(userPage.getByText(/Requested membership/i)).toBeVisible()

  // --- Admin: approve the pending request -------------------------------
  await nav(page, '/roles')
  await page.getByTestId(`manage-${roleName}`).click()
  const approve = page.locator('[data-testid^="approve-"]').first()
  await expect(approve).toBeVisible()
  await approve.click()
  await expect(page.getByText(/Approved — membership granted/i)).toBeVisible()

  // The new user now appears in the role's member list.
  await expect(page.getByRole('cell', { name: userLogin, exact: true })).toBeVisible()

  await userCtx.close()
})

test('multi-account: add a second account and switch between them', async ({ page, browser }) => {
  const sfx = uniqueSuffix()
  const login = `multi${sfx}`
  const email = `multi${sfx}@localhost`
  const pass = 'Multi!Acct-9x'

  // Admin creates an invite; a throwaway user registers (separate context).
  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await nav(page, '/admin/invites')
  await page.getByTestId('invite-email').fill(email)
  await page.getByTestId('invite-generate').click()
  const token = await page.getByTestId('invite-token-field').inputValue()

  const regCtx = await browser.newContext()
  const rp = await regCtx.newPage()
  await rp.goto(`/#/register?token=${encodeURIComponent(token)}`)
  await rp.getByTestId('reg-login').fill(login)
  await rp.getByTestId('reg-email').fill(email)
  await rp.getByTestId('reg-password').fill(pass)
  await rp.getByTestId('reg-submit').click()
  await expect(rp.getByTestId('login-input')).toBeVisible()
  await regCtx.close()

  // In the admin's browser: Add account → sign in as the new user.
  await page.getByTestId('account-chip').click()
  await page.getByRole('button', { name: '+ Add account' }).click()
  await expect(page.getByTestId('login-input')).toBeVisible()
  await submitLogin(page, login, pass, email)
  await expect(page.getByTestId('welcome')).toContainText(login)

  // Both accounts are listed in the switcher.
  await page.getByTestId('account-chip').click()
  await expect(page.getByTestId(`account-${ADMIN.login}`)).toBeVisible()
  await expect(page.getByTestId(`account-${login}`)).toBeVisible()

  // Switch back to admin.
  await page.getByTestId(`account-${ADMIN.login}`).locator('.account-pick').click()
  await expect(page.getByTestId('welcome')).toContainText(ADMIN.login)

  // And switch to the second account again.
  await page.getByTestId('account-chip').click()
  await page.getByTestId(`account-${login}`).locator('.account-pick').click()
  await expect(page.getByTestId('welcome')).toContainText(login)
})

test('forgot-password reset flow works end to end', async ({ page, browser }) => {
  const sfx = uniqueSuffix()
  const login = `reset${sfx}`
  const email = `reset${sfx}@localhost`
  const firstPass = 'First!Reset-9a'
  const newPass = 'Second!Reset-9b'

  // Admin creates an invite for the throwaway user.
  await signIn(page, ADMIN.login, ADMIN.password, ADMIN.email)
  await nav(page, '/admin/invites')
  await page.getByTestId('invite-email').fill(email)
  await page.getByTestId('invite-generate').click()
  const token = await page.getByTestId('invite-token-field').inputValue()

  const ctx = await browser.newContext()
  const up = await ctx.newPage()
  await up.goto(`/#/register?token=${encodeURIComponent(token)}`)
  await up.getByTestId('reg-login').fill(login)
  await up.getByTestId('reg-email').fill(email)
  await up.getByTestId('reg-password').fill(firstPass)
  await up.getByTestId('reg-submit').click()
  await expect(up.getByTestId('login-input')).toBeVisible()

  // Forgot-password: an OTP is capped, consumed after the cap, and a resend
  // replaces it with a fresh credential before a password may be changed.
  await clearMail()
  await up.goto('/#/reset')
  await up.locator('.input').first().fill(login)
  await up.getByRole('button', { name: /email me a code/i }).click()
  const firstCode = await waitForOtp(email, 'reset')
  await up.getByRole('button', { name: /set new password/i }).waitFor()
  let inputs = up.locator('.input')
  await inputs.nth(1).fill(newPass)
  for (let attempt = 0; attempt < 3; attempt += 1) {
    await inputs.nth(0).fill('000000')
    const wrong = up.waitForResponse((response) => response.url().includes('/password/reset/complete'))
    await up.getByRole('button', { name: /set new password/i }).click()
    expect((await wrong).status()).toBe(401)
  }
  await inputs.nth(0).fill(firstCode)
  const capped = up.waitForResponse((response) => response.url().includes('/password/reset/complete'))
  await up.getByRole('button', { name: /set new password/i }).click()
  expect((await capped).status()).toBe(401)

  await up.getByRole('button', { name: /use a different login/i }).click()
  await clearMail()
  await up.getByRole('button', { name: /email me a code/i }).click()
  const freshCode = await waitForOtp(email, 'reset')
  inputs = up.locator('.input')
  await inputs.nth(0).fill(freshCode)
	await inputs.nth(1).fill('weak')
	const policyFailure = up.waitForResponse((response) => response.url().includes('/password/reset/complete'))
	await up.getByRole('button', { name: /set new password/i }).click()
	expect((await policyFailure).status()).toBe(400)
	await expect(up.getByRole('button', { name: /set new password/i })).toBeVisible()
	// Policy failure rolls back the transaction; the exact same OTP can be
	// retried with a valid password and is consumed only with that mutation.
	await inputs.nth(0).fill(freshCode)
  await inputs.nth(1).fill(newPass)
  await up.getByRole('button', { name: /set new password/i }).click()
  await expect(up.getByTestId('login-input')).toBeVisible()

  // Sign in with the new password.
  await signIn(up, login, newPass, email)
  await expect(up.getByTestId('welcome')).toContainText(login)

  await ctx.close()
})
