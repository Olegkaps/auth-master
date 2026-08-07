import assert from 'node:assert/strict'
import test from 'node:test'

import { classifyRefreshResponse } from './refresh-outcome.js'

test('only 401 is a definitive server-side invalidation', () => {
  assert.deepEqual(classifyRefreshResponse(401, { error: 'invalid refresh token' }), { kind: 'invalid', status: 401 })
  for (const status of [400, 403, 408, 429, 500, 502, 503, 504]) {
    assert.equal(classifyRefreshResponse(status, { error: 'temporary' }).kind, 'transient')
  }
})

test('successful refresh requires a complete token payload', () => {
  assert.deepEqual(classifyRefreshResponse(200, {
    access_token: 'access', refresh_token: 'refresh', expires_at: '2030-01-01T00:00:00Z',
  }), {
    kind: 'ok', status: 200, accessToken: 'access', refreshToken: 'refresh', expiresAt: '2030-01-01T00:00:00Z',
  })
  for (const payload of [null, {}, { access_token: 'access' }, { access_token: '', refresh_token: 'refresh', expires_at: 'soon' }, 'not-json']) {
    assert.equal(classifyRefreshResponse(200, payload).kind, 'transient')
  }
})
