# AGENTS.md — auth-master

Demo authentication service: Go backend (chi, GORM, PostgreSQL, JWT, email OTP,
multi-parent RBAC, and Swagger), framework-free Vite/TypeScript SPA, and
Playwright end-to-end tests.

## Testing requirements

**Every new feature, behavior change, and bug fix must include unit,
integration, and E2E tests.** Every fix must add a regression test that fails
before the fix and passes afterward. Unit-test validation and decision logic,
integration-test persistence and HTTP behavior, and add or update a Playwright
journey for the user-visible workflow. If a layer genuinely does not apply,
document why in the change. Work is not complete until all applicable test
layers are present and pass.

Run tests only through `make`. Never invoke `go test`, `npx playwright`,
Podman, or Docker directly.

| Command | Purpose |
| --- | --- |
| `make lint` | Go format/vet/golangci-lint and TypeScript ESLint/type-checking |
| `make test-unit` | Fast Go tests without a database |
| `make test-race` | Go unit tests with the race detector |
| `make test-integration` | Go integration tests and coverage gate with PostgreSQL and Mailpit |
| `make test-e2e` | Playwright UI tests with an automatically managed stack |
| `make test-fuzz` | Short fuzz smoke tests used by CI |
| `make test` | Full lint, race, fuzz, integration, and E2E suite with a final summary |

Each group must print an actionable summary. Go groups use `gotestsum` and E2E
uses Playwright's `list` reporter. `make test` runs every group even when an
earlier group fails.

E2E runs the backend with `ACCESS_TOKEN_TTL=20s` to exercise transparent token
refresh. See [web/e2e/README.md](web/e2e/README.md).

## Development commands

| Command | Purpose |
| --- | --- |
| `make install` | Install Go tools, web dependencies, and Playwright Chromium |
| `make env-file` | Create an ignored `.env` from `.env.example` if it is missing |
| `make up` / `make down` | Start or stop PostgreSQL, Mailpit, and authd |
| `make dev` | Start infrastructure and run the backend locally |
| `make web-dev` | Start the Vite development server on port 5173 |
| `make swagger` | Regenerate committed OpenAPI artifacts after API changes |
| `make web-build` | Build the production SPA bundle |
| `make docker-build` | Build the production authd image through Compose |

`COMPOSE` selects Podman when available and Docker otherwise. Override it with,
for example, `make up COMPOSE='docker compose'`.

Compose-backed targets automatically run `make env-file`, so clean CI checkouts
do not need to commit or manually create `.env`.

## Pre-merge verification

`make check` is the fast gate (`make lint` plus `make test-integration`). Run
`make test` for the complete suite.

## Architecture

- `internal/service` — authentication, RBAC, invites, magic links, and OTP logic.
- `internal/repository` — GORM/PostgreSQL persistence and schema migration.
- `internal/transport/http` — chi routing, handlers, and Swagger annotations.
- `internal/testutil` — ephemeral database helpers for integration tests.
- `web/src` — framework-free SPA; `web/e2e` — Playwright user journeys.

Roles form a DAG. `role_mounts` stores multiple parent edges; membership and
role-admin authority inherit from every ancestor. Reject cycles before adding a
mount, and keep inheritance queries bounded and cycle-safe.

`direct_member` grants only the selected role; `member` and `role_admin`
inherit to descendants. Adding or removing a mount requires the actor to manage
both roles (superusers bypass this rule). `role_tags` defines the normalized
arbitrary tags available for a role; it does not grant them. `user_role_tags`
stores the subset granted to each membership. Granted tags inherit to
descendants only when the membership level itself inherits.

User and role lists use keyset pagination ordered by normalized name plus UUID.
Only a request without `cursor` runs `COUNT(*)`; later pages return and consume
an opaque cursor and must never use `OFFSET` or repeat the count query.

Change role-tag definitions only through single-tag POST/DELETE operations on
`(role_id, tag)` pairs; never add a bulk replacement endpoint. Deleting a
definition disables authorization but must not delete matching
`user_role_tags`; re-adding the definition restores the preserved grant and its
normal inheritance behavior.

Membership-tag grants are also single-pair POST/DELETE operations; never replace
the membership's complete tag set. Renaming a role tag is an atomic operation
that migrates matching membership grants from the old name to the new name.

Role checks use one recursive SQL query with a depth and cycle guard. With
10,000 roles and hierarchy depth 10, it traverses the target's ancestors rather
than the full role table, so do not add a cache without measurements showing a
need. A cache would need invalidation on memberships, expiry, hierarchy edges,
tag changes, bans, and role deletion.

User bans are superuser-only, revoke refresh sessions, and are checked on every
authenticated request. Service-layer token verification, magic-link completion,
role/tag checks, and manager/superuser checks must also reject banned users so
non-HTTP callers cannot bypass the ban. Do not weaken this to refresh-time-only
enforcement.

Superusers cannot be banned. Cross-service authorization uses the public POST
`/v1/auth/has-role` and `/v1/auth/has-role-with-tag` endpoints with a human
access token in the JSON body; derive the subject from the verified token and
never accept a caller-supplied user ID.

Service accounts are created only through the explicit superuser-only
`CreateServiceAccount` business operation. Hash secrets and persist the service
kind plus `superuser` flag atomically. Admin and Role transports accept a
verified human access JWT or service JWT as the actor; Identity and Session stay
human-only, and unknown RPCs remain default-deny. On HTTP mutations, bypass CSRF
only after verifying a bearer as a service JWT; never treat the presence of an
Authorization header as a bypass.

`BOOTSTRAP_SUPERUSER_SERVICE_LOGIN` and
`BOOTSTRAP_SUPERUSER_SERVICE_SECRET` are an idempotent demo-automation pair.
An existing account is accepted only when it is the same active superuser
service and its hash matches the configured secret. Never replace, return, or
log that credential.
