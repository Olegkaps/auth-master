/** Classify a refresh response without mutating session state. */
export function classifyRefreshResponse(status, payload) {
  if (status === 401) return { kind: 'invalid', status }
  if (status !== 200) return { kind: 'transient', status, reason: `unexpected HTTP ${status}` }
  if (!payload || typeof payload !== 'object') return { kind: 'transient', status, reason: 'malformed response' }
  const { access_token: accessToken, refresh_token: refreshToken, expires_at: expiresAt } = payload
  if (typeof accessToken !== 'string' || !accessToken || typeof refreshToken !== 'string' || !refreshToken || typeof expiresAt !== 'string' || !expiresAt) {
    return { kind: 'transient', status, reason: 'malformed response' }
  }
  return { kind: 'ok', status, accessToken, refreshToken, expiresAt }
}
