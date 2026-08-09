import { expect, test, type APIRequestContext } from '@playwright/test'
import { ADMIN, clearMail, uniqueSuffix, waitForOtp } from './helpers'

async function humanAdminToken(request: APIRequestContext): Promise<{ accessToken: string; csrfToken: string }> {
  await clearMail()
  const password = await request.post('/v1/auth/login', { data: { login: ADMIN.login, password: ADMIN.password } })
  expect(password.status()).toBe(200)
  const challenge = ((await password.json()) as { login_challenge: string }).login_challenge
  const code = await waitForOtp(ADMIN.email)
  const verified = await request.post('/v1/auth/login/verify-otp', {
    data: { challenge, code, device_id: `service-e2e-${uniqueSuffix()}`, device_label: 'service API E2E' },
  })
  expect(verified.status()).toBe(200)
  const body = (await verified.json()) as { access_token: string; csrf_token: string }
  return { accessToken: body.access_token, csrfToken: body.csrf_token }
}

test('service actors are explicit, scoped, and preserve human-only boundaries', async ({ request }) => {
  const suffix = uniqueSuffix()
  const human = await humanAdminToken(request)
  const adminHeaders = {
    Authorization: `Bearer ${human.accessToken}`,
    'X-CSRF-Token': human.csrfToken,
  }
  const superLogin = `e2e-super-service-${suffix}`
  const superSecret = 'E2E-Super-Service1!'
  const ordinaryLogin = `e2e-service-${suffix}`
  const ordinarySecret = 'E2E-Ordinary-Service1!'

  const humanWithoutCSRF = await request.post('/v1/roles', {
    headers: { Authorization: `Bearer ${human.accessToken}` },
    data: { name: `csrf-must-fail-${suffix}`, description: '', parent_ids: [] },
  })
  expect(humanWithoutCSRF.status()).toBe(403)

  const createSuper = await request.post('/v1/admin/service-accounts', {
    headers: adminHeaders,
    data: { login: superLogin, secret: superSecret, superuser: true },
  })
  expect(createSuper.status()).toBe(201)
  const createOrdinary = await request.post('/v1/admin/service-accounts', {
    headers: adminHeaders,
    data: { login: ordinaryLogin, secret: ordinarySecret, superuser: false },
  })
  expect(createOrdinary.status()).toBe(201)

  const superTokenResponse = await request.post('/v1/auth/service-token', { data: { login: superLogin, secret: superSecret } })
  expect(superTokenResponse.status()).toBe(200)
  const superToken = ((await superTokenResponse.json()) as { access_token: string }).access_token
  const ordinaryTokenResponse = await request.post('/v1/auth/service-token', { data: { login: ordinaryLogin, secret: ordinarySecret } })
  expect(ordinaryTokenResponse.status()).toBe(200)
  const ordinaryToken = ((await ordinaryTokenResponse.json()) as { access_token: string }).access_token

  const serviceHeaders = { Authorization: `Bearer ${superToken}` }
  const createdByService = await request.post('/v1/admin/service-accounts', {
    headers: serviceHeaders,
    data: { login: `e2e-child-service-${suffix}`, secret: 'E2E-Child-Service1!', superuser: false },
  })
  expect(createdByService.status()).toBe(201)
  const roleCreatedByService = await request.post('/v1/roles', {
    headers: serviceHeaders,
    data: { name: `e2e-service-role-${suffix}`, description: 'created by service actor', parent_ids: [] },
  })
  expect(roleCreatedByService.status()).toBe(201)

  expect((await request.get('/v1/me', { headers: serviceHeaders })).status()).toBe(401)
  expect((await request.get('/v1/sessions', { headers: serviceHeaders })).status()).toBe(401)
  expect((await request.post('/v1/auth/has-role', { data: { token: superToken, role_name: `e2e-service-role-${suffix}` } })).status()).toBe(401)

  const ordinaryHeaders = { Authorization: `Bearer ${ordinaryToken}` }
  expect((await request.post('/v1/admin/service-accounts', {
    headers: ordinaryHeaders,
    data: { login: `forbidden-service-${suffix}`, secret: 'Forbidden-Service1!', superuser: false },
  })).status()).toBe(403)
  expect((await request.post('/v1/roles', {
    headers: ordinaryHeaders,
    data: { name: `forbidden-role-${suffix}`, description: '', parent_ids: [] },
  })).status()).toBe(403)
})
