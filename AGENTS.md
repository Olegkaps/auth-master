# AGENTS.md — auth-master

Demo authentication service: Go backend (chi, GORM, PostgreSQL, JWT, email OTP,
multi-parent RBAC, and Swagger), framework-free Vite/TypeScript SPA, and
Playwright end-to-end tests.

## Testing requirements

**Every new feature or behavior change must include automated tests.** Add tests
at the appropriate Go layer and always add or update a Playwright E2E test for a
user-visible feature. A feature is not complete without its tests.

Run tests only through `make`. Never invoke `go test`, `npx playwright`,
Podman, or Docker directly.

| Command | Purpose |
| --- | --- |
| `make lint` | Go format/vet/golangci-lint and TypeScript ESLint/type-checking |
| `make test-unit` | Fast Go tests without a database |
| `make test-race` | Go unit tests with the race detector |
| `make test-integration` | Go integration tests and coverage gate with PostgreSQL and Mailpit |
| `make test-e2e` | Playwright UI tests with an automatically managed stack |
| `make test` | Full lint, race, integration, and E2E suite with a final summary |

Each group must print an actionable summary. Go groups use `gotestsum` and E2E
uses Playwright's `list` reporter. `make test` runs every group even when an
earlier group fails.

E2E runs the backend with `ACCESS_TOKEN_TTL=20s` to exercise transparent token
refresh. See [web/e2e/README.md](web/e2e/README.md).

## Development commands

| Command | Purpose |
| --- | --- |
| `make install` | Install Go tools, web dependencies, and Playwright Chromium |
| `make up` / `make down` | Start or stop PostgreSQL, Mailpit, and authd |
| `make dev` | Start infrastructure and run the backend locally |
| `make web-dev` | Start the Vite development server on port 5173 |
| `make swagger` | Regenerate committed OpenAPI artifacts after API changes |

`COMPOSE` selects Podman when available and Docker otherwise. Override it with,
for example, `make up COMPOSE='docker compose'`.

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
