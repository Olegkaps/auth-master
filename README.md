# auth-master

A demonstration authentication and authorization service with a Go REST API,
PostgreSQL, JWT access/refresh sessions, email OTP, passwordless magic links,
registration invites, multi-parent RBAC, Swagger, Prometheus metrics, and a
framework-free TypeScript SPA.

## Requirements

- Go 1.24 or newer
- Podman or Docker with Compose
- Node.js 20 or newer
- GNU Make

## Quick start

```bash
cp .env.example .env
make install
make up
```

The backend and SPA are available at `http://localhost:8080`, Swagger UI at
`http://localhost:8080/swagger/`, and Mailpit at `http://localhost:8025`.

For local development, run these commands in separate terminals:

```bash
make dev
make web-dev
```

Compose is selected automatically (Podman first, then Docker). Override it when
needed: `make up COMPOSE='docker compose'`.

## Security model

- Passwords require upper- and lowercase letters, a number, and a special
  character. Password history and Levenshtein similarity checks prevent reuse.
- Login is password plus a single-use email OTP challenge. An incorrect OTP
  consumes the challenge.
- Password changes require the current password and a separate email OTP.
- Magic links are single-use, time-limited passwordless login tokens stored as
  hashes.
- Refresh tokens rotate and are scoped to a stable browser device identifier.
- Signing keys can rotate; clients transparently refresh stale access tokens.
- State-changing cookie-authenticated requests use CSRF protection.

All configuration variables and defaults are documented in `.env.example` and
`internal/config/config.go`.

## Multi-parent role mounting

Roles form a directed acyclic graph instead of a single-parent tree. A role can
be mounted under any number of parent roles. Membership and `role_admin`
authority flow downward through every parent path:

```text
engineering ─┐
             ├─> release-manager
operations ──┘
```

A member of either parent has `release-manager`; an administrator of either
parent can manage it. Authority never flows upward or sideways.

Mount edges live in `role_mounts(child_role_id, parent_role_id)`. Recursive
queries evaluate inheritance live, stop at depth 64, and avoid revisiting a role
within a path. A mount that would create a cycle is rejected. During migration,
legacy `roles.parent_id` values are copied into `role_mounts`.

Relevant endpoints:

- `GET /v1/roles` — list roles and all `ParentIDs`.
- `POST /v1/roles/{roleID}/mounts` — add a parent without replacing other mounts.
- `DELETE /v1/roles/{roleID}/mounts/{parentID}` — remove one mount.
- `PATCH /v1/roles/{roleID}/parent` — compatibility endpoint that replaces all
  mounts with zero or one parent.
- `GET /v1/me/has-role?role_name=...` — resolve direct or inherited membership.
- `GET /v1/roles/{roleID}/members` — list direct active members.

Deleting a role removes its memberships and requests. Its direct children are
mounted under each of its direct parents before the deleted role's edges are
removed, preserving reachability where possible.

## SPA

`web/` is a Vite/TypeScript demonstration client without a UI framework. It
shows login and email OTP, password reset, magic-link login, multi-account
switching, session management, invites, signing-key rotation, and RBAC.

The Roles page lists every parent mount. Superusers can mount a role under
additional parents or remove individual mounts. Role managers can manage
members and pending membership requests.

The client keeps access tokens in memory and restores sessions using refresh
tokens. The demo's multi-account support stores per-account refresh tokens in
local storage; a production browser application should prefer a server-managed
HttpOnly design to reduce XSS exposure.

## Tests and quality gates

Run every check through `make`:

| Command | Purpose |
| --- | --- |
| `make lint` | Go formatting, vet, golangci-lint, ESLint, and TypeScript checks |
| `make test-unit` | Fast Go tests without PostgreSQL |
| `make test-race` | Unit tests with Go's race detector |
| `make test-integration` | PostgreSQL integration tests and the coverage gate |
| `make test-e2e` | Playwright browser tests against a real stack |
| `make check` | Fast pre-merge lint and integration gate |
| `make test` | Complete suite with a final per-group summary |

Every feature must include automated tests, including E2E coverage for visible
behavior. See [AGENTS.md](AGENTS.md) and [web/e2e/README.md](web/e2e/README.md).

## OpenAPI

Handler annotations generate `docs/docs.go`, `docs/swagger.json`, and
`docs/swagger.yaml`. After changing routes or request/response types, run:

```bash
make swagger
```

## Project layout

- `cmd/authd` — process entry point and API metadata.
- `internal/config` — environment configuration.
- `internal/domain` — domain data types.
- `internal/repository` — PostgreSQL persistence and migrations.
- `internal/service` — authentication and authorization rules.
- `internal/transport/http` — REST transport and middleware.
- `internal/testutil` — integration-test infrastructure.
- `web/src` — SPA source.
- `web/e2e` — Playwright tests.
- `docs` — generated OpenAPI artifacts.
