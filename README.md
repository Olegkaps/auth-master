# auth-master

A demonstration authentication and authorization service with Go REST and gRPC APIs,
PostgreSQL, JWT access/refresh sessions, email OTP, passwordless magic links,
registration invites, multi-parent RBAC, Swagger, Prometheus metrics, and a
framework-free TypeScript SPA.

## Requirements

- Go 1.25 or newer
- Protocol Buffers compiler (`protoc`) for `make proto` and `make proto-check`
- Podman or Docker with Compose
- Node.js 20 or newer
- GNU Make

## Quick start

```bash
cp .env.example .env
make install
make up
```

The production SPA and API gateway are available at `http://localhost:8080`, Swagger UI at
`http://localhost:8080/swagger/`, gRPC at `localhost:9090`, and Mailpit at
`http://localhost:8025`.

## gRPC for backend consumers

The checked-in `api/auth/v1/auth.proto` contract exposes all 54 business
operations as five unary services: `AuthService`, `IdentityService`,
`SessionService`, `AdminService`, and `RoleService`. Health uses standard
`grpc.health.v1.Health`. HTTP health, metrics, and Swagger routes remain
HTTP-only.

Import the generated Go client directly from this module; there is no separate
SDK:

```go
import (
    "context"
    "time"

    authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    "google.golang.org/grpc/metadata"
)

conn, err := grpc.NewClient(
    "localhost:9090",
    grpc.WithTransportCredentials(insecure.NewCredentials()), // local development only
)
if err != nil { /* handle */ }
defer conn.Close()

ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
defer cancel()
ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+humanAccessToken)
me, err := authv1.NewIdentityServiceClient(conn).GetMe(ctx, &authv1.GetMeRequest{})
```

For TLS, set both `GRPC_TLS_CERT_FILE` and `GRPC_TLS_KEY_FILE` on authd and use
`credentials.NewClientTLSFromFile` in the client. Setting only one server file
is a startup error. Plaintext credentials are for trusted local development
only. The host address is `localhost:${GRPC_PORT:-9090}`; from another Compose
service it is `authd:9090`. The nginx SPA gateway proxies REST only.

For Compose TLS, keep the certificate and key outside the image and mount them
read-only with an override such as `docker-compose.override.yml`:

```yaml
services:
  authd:
    environment:
      GRPC_TLS_CERT_FILE: /run/grpc-tls/server.crt
      GRPC_TLS_KEY_FILE: /run/grpc-tls/server.key
    volumes:
      - ./certs/server.crt:/run/grpc-tls/server.crt:ro
      - ./certs/server.key:/run/grpc-tls/server.key:ro
```

The production container runs as UID/GID `65532:65532`. Make the private key
readable by that identity but not other users (for example, owner `65532` and
mode `0400`, or an equivalent group-readable `0440` arrangement); a certificate
may be `0444`. The certificate SANs must cover every client name in use, usually
`localhost` for host clients and `authd` for clients in the Compose network.
Configure the client's TLS server name to match the selected SAN.

Identity, Session, Admin, and Role RPCs require a human access JWT in
`authorization` metadata. The actor comes only from verified JWT `sub`; request
messages never accept an actor ID. Service JWTs are valid for issuance and
`InspectToken` but are rejected by human and RBAC RPCs. `CheckTokenRole` and
`CheckTokenRoleWithTag` are intentionally different: put the end user's human
token in the `access_token` message field, not metadata. The service evaluates
that token's subject without trusting a caller-supplied user ID.

Banning a user increments that account's token version and revokes every
refresh session immediately. Existing REST and gRPC bearer tokens therefore
remain invalid after an unban; the user must authenticate again to receive
credentials for the new version. Unbanning restores login, not old sessions.

Always set a deadline. Retry read-only queries and health checks only for
transient `UNAVAILABLE` failures. Creation, rotation, grants, revocation,
password, refresh, and OTP flows have no general idempotency key and must not be
blindly retried. Errors use canonical status codes plus stable
`google.rpc.ErrorInfo`; secret credentials are never returned in errors.

`StartStepUp2FA.ttl` defaults to five minutes when absent or zero, accepts
values through 24 hours, and rejects negative or larger values.
`CreateRegistrationInvite.ttl` defaults to 24 hours when absent or zero and
rejects negative or unrepresentable durations. `AssignRole.valid_until`, when
present, must be strictly in the future and an invalid value cannot replace an
existing membership. Role requests transition once from pending to approved or
rejected; a second decision returns `FAILED_PRECONDITION` with
`REQUEST_NOT_PENDING`. Paginated list totals are present only on the first
request, while subsequent requests carry the opaque `next_cursor`.

Reflection is disabled by default; set `GRPC_REFLECTION=true` only in a trusted
development environment. `grpc.health.v1.Health/Check` reports `SERVING` after
bootstrap and both listeners are bound, and `NOT_SERVING` during graceful
shutdown.

Use `make proto` to lint and regenerate the contract. `make proto-check` fails
when generated Go files drift or the contract breaks the committed
`api/auth/v1/auth-v1-baseline.binpb` descriptor; run the standalone check with
`make proto-breaking`. `make proto` never changes the baseline. Advance it only
after an explicit compatibility review with `make proto-baseline-update`, then
review and commit the binary diff separately.

For local development with Vite hot reload, run these commands in separate
terminals and open `http://localhost:5173`:

```bash
make dev
make web-dev
```

Compose is selected automatically (Podman first, then Docker). Override it when
needed: `make up COMPOSE='docker compose'`.

`make down` stops the stack but preserves the named PostgreSQL volume. Remove
that volume explicitly only when you intentionally want to erase local data.

### Role-name migration preflight

Role names are authorization keys and must be nonblank and unique after
case-folding and trimming surrounding whitespace. Startup takes an exclusive
lock on `roles`, checks the complete legacy table, and refuses to migrate when
it finds blank names or normalized collisions. The error lists every affected
role UUID and original value. It never silently merges, suffixes, or otherwise
changes ambiguous authorization keys.

Repair the listed `roles.name` values so they are nonblank and
case-insensitively unique, then restart or rerun the migration. When the
preflight is clean, nonambiguous surrounding whitespace is trimmed
deterministically and database constraints prevent regressions.

The explicit copy is optional: every Compose-backed Make target creates the
ignored `.env` from `.env.example` when it is missing and never overwrites an
existing developer file.

## Security model

- Passwords require upper- and lowercase letters, a number, and a special
  character. Password history and Levenshtein similarity checks prevent reuse.
- Login is password plus a single-use email OTP challenge. An incorrect OTP
  consumes the challenge.
- Password-reset OTPs allow at most `OTP_MAX_ATTEMPTS` wrong codes (five by
  default), and reset issuance is throttled by `OTP_RESET_MIN_INTERVAL` (one
  minute by default). The public start endpoint gives the same response for
  unknown, throttled, and known accounts to avoid account enumeration.
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

Membership levels are deliberately distinct:

- `direct_member` grants only the selected role and never inherits.
- `member` grants the selected role and every descendant.
- `role_admin` grants inherited membership and management authority over the
  selected role and every descendant.

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
removed, preserving reachability where possible. Tag definitions for the deleted
role are removed as part of the same transaction.

Hierarchy writes are serialized in PostgreSQL and cycle-checked in the same
transaction as the mount. Creating a role with multiple parents is atomic: an
invalid parent leaves no partial role behind. Adding or removing a mount requires
the caller to manage both endpoint roles; superusers bypass that check.

## Role tags and grants

Role tags are normalized capability names. A definition in
`role_tags(role_id, tag)` only makes a tag available; it does not grant the
capability. A grant is a separate `user_role_tags(user_role_id, tag)` pair and
must be a subset of the role's definitions.

- Add or delete definitions with the single-pair `POST`/`DELETE
  /v1/roles/{roleID}/tags` operations.
- Add or delete membership grants with the single-pair `POST`/`DELETE
  /v1/roles/{roleID}/members/{userID}/tags` operations.
- Rename a definition with `PATCH /v1/roles/{roleID}/tags`; matching membership
  grants migrate atomically.
- Deleting a definition disables authorization but preserves matching membership
  grants. Re-adding the same definition restores the preserved grant.
- A granted tag inherits to descendants only when its membership level inherits;
  `direct_member` tags stay local.

## Pagination and authorization APIs

`GET /v1/roles` and superuser-only `GET /v1/admin/users` use keyset pagination
ordered by normalized name and UUID. `page_size` is at most 100. The first page
returns `total` and an opaque `next_cursor`; cursor pages return `total: null` and
never use an offset or repeat the count query. Searches are case-insensitive.

`GET /v1/roles/{roleID}/subgroups?recursive=false` returns direct children;
`recursive=true` returns all descendants once even through multiple paths.

For cross-service authorization, send a human access token in the JSON body to
`POST /v1/auth/has-role` or `POST /v1/auth/has-role-with-tag`. The subject is
always derived from the verified token; callers cannot supply a user ID. Service,
invalid, stale, and banned-user tokens are rejected.

User bans are superuser-only, cannot target the actor or another superuser, and
revoke every refresh session. Bans are checked on each authenticated request and
inside service-layer token, magic-link, role/tag, and management checks. Unban is
also routed through the service authorization boundary.

## SPA

`web/` is a Vite/TypeScript demonstration client without a UI framework. It
shows login and email OTP, password reset, magic-link login, multi-account
switching, session management, invites, signing-key rotation, and RBAC.

The Roles page lists every parent mount. Superusers can always add or remove
mounts. A role manager may do the same only when they manage both the child and
parent roles. Role managers can also manage members and pending membership
requests for roles under their authority.

The client keeps access tokens in memory and restores sessions using refresh
tokens. The demo's multi-account support stores per-account refresh tokens in
local storage; a production browser application should prefer a server-managed
HttpOnly design to reduce XSS exposure.

Saved accounts are removed only when refresh returns `401`, which definitively
means the refresh session is invalid. Network failures, malformed responses,
`408`, `429`, other unexpected statuses, and server `5xx` responses preserve
the saved account. A failed switch restores the previous account and reports a
retryable error; a transient failure during boot keeps the cached active
account so a later request or reload can retry.

## Tests and quality gates

Run every check through `make`:

| Command | Purpose |
| --- | --- |
| `make lint` | Go formatting, vet, golangci-lint, ESLint, and TypeScript checks |
| `make test-unit` | Fast Go tests without PostgreSQL |
| `make test-race` | Unit tests with Go's race detector |
| `make test-integration` | PostgreSQL integration tests and the coverage gate |
| `make test-e2e` | Playwright browser tests against a real stack |
| `make test-fuzz` | Short fuzz smoke tests used by CI |
| `make check` | Fast pre-merge lint and integration gate |
| `make test` | Complete suite with a final per-group summary |
| `make web-build` | Production SPA build |
| `make docker-build` | Production container-image build through Compose |

Every feature must include automated tests, including E2E coverage for visible
behavior. See [AGENTS.md](AGENTS.md) and [web/e2e/README.md](web/e2e/README.md).
PostgreSQL transaction semantics such as row-lock ordering, trigger rollback,
and deterministic history trimming are integration-only concerns and are
verified by `make test-integration`; policy preparation and error mapping stay
in the fast unit layer.

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
- `internal/transport/grpc` — typed gRPC transport and authentication boundary.
- `internal/transport/parity` — exact REST-to-RPC contract manifest.
- `api/auth/v1` — protobuf contract and committed Go client/server stubs.
- `internal/testutil` — integration-test infrastructure.
- `web/src` — SPA source.
- `web/e2e` — Playwright tests.
- `docs` — generated OpenAPI artifacts.
