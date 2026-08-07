export type RefreshOutcome =
  | { kind: 'ok'; status: 200; accessToken: string; refreshToken: string; expiresAt: string }
  | { kind: 'invalid'; status: number }
  | { kind: 'transient'; status: number; reason: string }

export function classifyRefreshResponse(status: number, payload: unknown): RefreshOutcome
