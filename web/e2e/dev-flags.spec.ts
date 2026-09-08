import { expect, test } from '@playwright/test'
import { ADMIN, nav, uniqueSuffix } from './helpers'

test('open registration and skipped password OTP form a no-mail-code sign-in journey', async ({ page }) => {
  test.skip(process.env.E2E_REGISTRATION_OPEN !== 'true' || process.env.E2E_SKIP_LOGIN_OTP !== 'true', 'requires both opt-in backend flags')

  const suffix = uniqueSuffix()
  const login = `open${suffix}`
  const email = `${login}@localhost`
  const password = 'Open-Registration9!'

  await page.goto('/#/register')
  await expect(page.getByTestId('registration-policy')).toContainText('Registration is open')
  await expect(page.getByTestId('reg-token')).toBeHidden()
  await page.getByTestId('reg-login').fill(login)
  await page.getByTestId('reg-email').fill(email)
  await page.getByTestId('reg-password').fill(password)
  await page.getByTestId('reg-submit').click()

  await expect(page.getByTestId('login-input')).toBeVisible()
  await page.getByTestId('login-input').fill(login)
  await page.getByTestId('password-input').fill(password)
  await page.getByTestId('continue-btn').click()
  await expect(page.getByTestId('dashboard')).toBeVisible()
  await expect(page.getByTestId('otp-input')).toHaveCount(0)
})

test('an explicit invalid invite stays strict while registration is open', async ({ page }) => {
  test.skip(process.env.E2E_REGISTRATION_OPEN !== 'true', 'requires open-registration backend')

  const suffix = uniqueSuffix()
  await page.goto('/#/register?token=explicitly-invalid')
  await expect(page.getByTestId('reg-token')).toBeVisible()
  await expect(page.getByText(/invalid or expired/i)).toBeVisible()
  await page.getByTestId('reg-login').fill(`strict${suffix}`)
  await page.getByTestId('reg-email').fill(`strict${suffix}@localhost`)
  await page.getByTestId('reg-password').fill('Strict-Invite9!')
  await page.getByTestId('reg-submit').click()
  await expect(page.getByText(/invalid or expired invite/i)).toBeVisible()

  await page.getByTestId('discard-invite').click()
  await expect(page).toHaveURL(/\/#\/register$/)
  await expect(page.getByTestId('reg-token')).toBeHidden()
  await expect(page.getByTestId('registration-policy')).toContainText('Registration is open')
  await page.getByTestId('reg-submit').click()
  await expect(page.getByTestId('login-input')).toBeVisible()
})

test('a selected email-locked invite keeps its email read-only', async ({ page, browser }) => {
  test.skip(process.env.E2E_REGISTRATION_OPEN !== 'true' || process.env.E2E_SKIP_LOGIN_OTP !== 'true', 'requires the opt-in backend profile')

  const email = `locked${uniqueSuffix()}@localhost`
  await page.goto('/#/login')
  await page.getByTestId('login-input').fill(ADMIN.login)
  await page.getByTestId('password-input').fill(ADMIN.password)
  await page.getByTestId('continue-btn').click()
  await expect(page.getByTestId('dashboard')).toBeVisible()
  await nav(page, '/admin/invites')
  await page.getByTestId('invite-email').fill(email)
  await page.getByTestId('invite-generate').click()
  const token = await page.getByTestId('invite-token-field').inputValue()

  const registrationContext = await browser.newContext()
  const registrationPage = await registrationContext.newPage()
  await registrationPage.goto(`/#/register?token=${encodeURIComponent(token)}`)
  await expect(registrationPage.getByText(/invite valid/i)).toBeVisible()
  await expect(registrationPage.getByTestId('reg-email')).toHaveValue(email)
  await expect(registrationPage.getByTestId('reg-email')).toHaveAttribute('readonly', '')
  await registrationContext.close()
})

test('registration stays disabled until policy resolution and ignores a stale preview', async ({ page }) => {
  let releaseInitial!: () => void
  let markInitialRequested!: () => void
  const initialGate = new Promise<void>((resolve) => {
    releaseInitial = resolve
  })
  const initialRequested = new Promise<void>((resolve) => {
    markInitialRequested = resolve
  })
  await page.route('**/v1/auth/registration-invite?*', async (route) => {
    const token = new URL(route.request().url()).searchParams.get('token') ?? ''
    if (token === '') {
      markInitialRequested()
      await initialGate
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ valid: false, registration_open: true }),
    })
  })

  await page.goto('/#/register')
  await initialRequested
  await expect(page.getByTestId('reg-submit')).toBeDisabled()
  releaseInitial()
  await expect(page.getByTestId('reg-submit')).toBeEnabled()
  await page.unrouteAll({ behavior: 'wait' })

  let releaseSlow!: () => void
  let markSlowRequested!: () => void
  const slowGate = new Promise<void>((resolve) => {
    releaseSlow = resolve
  })
  const slowRequested = new Promise<void>((resolve) => {
    markSlowRequested = resolve
  })
  await page.route('**/v1/auth/registration-invite?*', async (route) => {
    const token = new URL(route.request().url()).searchParams.get('token') ?? ''
    if (token === 'slow') {
      markSlowRequested()
      await slowGate
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ valid: true, registration_open: true, email: 'slow@example.test', expires_at: '2099-01-01T00:00:00Z' }),
      })
      return
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ valid: true, registration_open: true, email: 'fast@example.test', expires_at: '2099-01-01T00:00:00Z' }),
    })
  })

  await page.goto('/#/register?token=slow')
  await slowRequested
  await page.getByTestId('reg-token').fill('fast')
  await page.getByTestId('reg-token').press('Tab')
  await expect(page.getByTestId('reg-email')).toHaveValue('fast@example.test')
  const staleResponse = page.waitForResponse((response) => new URL(response.url()).searchParams.get('token') === 'slow')
  releaseSlow()
  await staleResponse
  await expect(page.getByTestId('reg-email')).toHaveValue('fast@example.test')
  await expect(page.getByText(/locked to fast@example\.test/i)).toBeVisible()
})

test('failed automatic empty-code continuation returns to a clean password step', async ({ page }) => {
  await page.route('**/v1/auth/login', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ otp_sent: false, login_challenge: 'single-use-challenge' }),
    })
  })
  await page.route('**/v1/auth/login/verify-otp', async (route) => {
    await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: 'invalid or expired otp' }) })
  })

  await page.goto('/#/login')
  await expect(page.getByTestId('login-alternatives')).toContainText('Depending on server policy')
  await page.getByTestId('login-input').fill('retry-me')
  await page.getByTestId('password-input').fill('Strong-Retry9!')
  await page.getByTestId('continue-btn').click()

  await expect(page.getByTestId('login-input')).toHaveValue('retry-me')
  await expect(page.getByTestId('password-input')).toHaveValue('')
  await expect(page.getByText(/automatic sign-in could not be completed/i)).toBeVisible()
  await expect(page.getByTestId('otp-input')).toHaveCount(0)
  await expect(page.getByText(/invalid or expired otp/i)).toHaveCount(0)
})
