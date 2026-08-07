# E2E UI tests (Playwright)

These tests drive the real SPA in a browser and exercise the key user journeys
against a live backend and Mailpit (OTP codes are read from Mailpit's API).

## Run (one command)

From the repo root:

```bash
make install     # first time only: deps + Playwright browser
make test-e2e    # brings up infra + backend, runs the suite, tears down
```

`make test-e2e` (via `scripts/e2e.sh`) starts Postgres + Mailpit through compose,
builds and runs the backend with a bootstrap superuser and a short
`ACCESS_TOKEN_TTL` (backend logs go to a temp file so the output is just the
Playwright summary — `X passed / Y failed` with per-test reasons), runs Playwright
(which starts the Vite dev server itself), then stops the backend and drops only
the isolated `auth_e2e` database. PostgreSQL and Mailpit remain running for
faster subsequent runs; use `make down` when you want to stop infrastructure.

Always launch tests through `make test-e2e`; pass a file or Playwright filter
through `E2E_ARGS`, for example `make test-e2e E2E_ARGS='extra.spec.ts'`.

## Configuration (env)

| Var | Default | Meaning |
| --- | --- | --- |
| `E2E_BASE_URL` | `http://localhost:5173` | SPA origin |
| `E2E_MAILPIT_URL` | `http://localhost:8025` | Mailpit API base |
| `E2E_ADMIN_LOGIN` | `admin` | bootstrap superuser login |
| `E2E_ADMIN_PASSWORD` | `Adm1n!Passw0rd123` | bootstrap superuser password |
| `E2E_ADMIN_EMAIL` | `admin@localhost` | bootstrap superuser email |

## What is covered

- Admin sign-in (password → email OTP) and admin-only dashboard.
- Passwordless login via a one-time email magic link (and its single-use replay rejection).
- Full RBAC lifecycle: create role → mint invite → register new user →
  user requests the role → admin approves → member appears in the role.
- Multi-account: add a second account and switch between them (incl. from the login form).
- Permissions: non-superuser has no admin surfaces and can't manage others' roles; a
  non-manager's request needs approval while a manager's is auto-granted; member
  list actions (promote / remove) and role deletion.
- Effective inherited membership and inherited role-admin UI state, including
  the non-inheriting `direct_member` level.
- Keyset pagination beyond the first page and uncapped role selectors with more
  than one hundred roles.
- Atomic membership plus initial tag grants, tag revocation, rename, definition
  delete/re-add preservation, and cross-service role/tag checks.
- Forgot-password reset: attempt cap and resend, policy rejection followed by a
  successful retry with the same code, then sign in with the new password.
- A wrong login OTP drops back to the password step (single OTP attempt).
- A superuser invite yields an account with admin access.
- One-click session revoke (no email OTP).
- Password change requires 2FA (email code); standalone step-up 2FA start → verify.
- Opening an invite link while signed in registers and adds another account.
- Staying signed in after the access token expires (transparent refresh).

### Access-token expiry test

`stays signed in after the access token expires` idles past the access-token TTL,
then acts and expects a transparent refresh. `make test-e2e` already sets this up:
the backend runs with `ACCESS_TOKEN_TTL=20s` and the test waits `E2E_ACCESS_TTL_SEC`
(default 20) seconds. Override either via env before `make test-e2e` if needed.

Tests run serially (`workers: 1`) because they share one Mailpit inbox.
