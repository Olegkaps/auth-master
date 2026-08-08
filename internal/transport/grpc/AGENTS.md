# AGENTS.md — gRPC transport

Typed unary gRPC v1 adapter for auth-master. **It shares service-layer use cases
with REST; do not reimplement authorization or business decisions here.**

## Purpose

This package exposes backend-to-backend access to every business operation in
the REST API while retaining the same authentication, RBAC, persistence, and
ban semantics.

## Architecture

- `server.go` — construction, default-deny authentication, recovery, status
  mapping, health, and opt-in reflection.
- `auth.go` — public authentication RPC wire adapters.
- `identity_session_admin.go` — human identity, session, and superuser adapters.
- `role.go` — actor-aware role and membership adapters.
- `convert.go` — protobuf/domain conversions and wire validation.
- `server_test.go` — descriptor, classification, status, and validation tests.
- `server_integration_test.go` — real PostgreSQL and TCP gRPC journey.

## Request flow

1. The unary interceptor classifies the exact RPC. Unknown methods are denied.
2. Human RPCs read one `authorization: Bearer <access JWT>` metadata value and
   derive the actor exclusively from the verified token subject.
3. The adapter validates protobuf values and invokes `internal/service`.
4. Domain results are converted to protobuf; errors become canonical status
   codes with stable `google.rpc.ErrorInfo` reasons.

## Extension rules

1. Add the typed RPC to `api/auth/v1/auth.proto` and regenerate committed code.
2. Add the REST-to-RPC mapping to `internal/transport/parity/manifest.go`.
3. Classify authentication explicitly; the default must remain deny.
4. Add or reuse a transport-neutral service use case for orchestration.
5. Add unit and integration coverage. Browser E2E applies only if the SPA
   workflow changes.

Keep refresh tokens, OTPs, passwords, service secrets, and access tokens out of
logs and error details. Reflection remains disabled unless configured.
