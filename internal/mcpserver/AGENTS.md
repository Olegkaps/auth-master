# AGENTS.md — MCP transport

Local stdio Model Context Protocol adapter for auth-master. **Keep credentials
out of tool inputs, schemas, output, logs, and errors.**

## Purpose

This package lets an MCP host administer auth-master through the existing typed
gRPC contract. It is an adapter only: authorization, validation, persistence,
and RBAC decisions remain in `internal/service` and the gRPC transport.

## Architecture

- `client.go` — gRPC client, environment configuration, TLS, deadlines, and
  in-memory service-token caching.
- `server.go` — MCP server construction, tool schemas and annotations, protobuf
  to model-facing DTO conversion.
- `server_test.go` — in-memory MCP protocol and closed-default validation tests.
- `server_integration_test.go` — PostgreSQL → service → gRPC → MCP journey.
- `cmd/auth-master-mcp` — stdio executable; stdout is protocol-only.

## Request flow

1. The executable reads the gRPC address and service credentials from its
   environment before opening stdio.
2. The typed MCP handler validates model arguments and calls the `Backend`
   interface.
3. `Client` mints and caches a short-lived service JWT internally, adds it as
   gRPC bearer metadata, and applies a deadline.
4. The existing gRPC interceptor verifies the service actor and the service
   layer enforces superuser or role-admin authority.
5. Successful protobuf results become small structured MCP outputs; upstream
   failures become MCP tool errors that a model can act on.

## Security boundaries

- Do not add authentication, OTP, password, refresh-token, signing-key,
  bootstrap, invite, or service-account-creation tools.
- Do not accept access tokens, service logins, or service secrets as tool
  parameters. Credentials belong only to process configuration.
- Stdio stdout must contain MCP messages only. Diagnostics go to stderr and
  must not include credentials or bearer tokens.
- Mark read operations `ReadOnlyHint`; mark revocation, replacement, bans, and
  deletes `DestructiveHint` so hosts can request appropriate approval.
- Plaintext gRPC is local-development-only. Preserve the explicit CA-backed TLS
  path for remote use.
- Never blindly retry mutations. The adapter refreshes before token expiry but
  does not replay a failed call.

## Extension rules

1. Reuse or extend the typed `auth.v1` gRPC API; do not reach into repositories
   or recreate business logic here.
2. Add a narrow method to `Backend` and `Client`, then convert protobuf values
   to credential-free MCP DTOs.
3. Give every tool accurate read-only and destructive annotations and precise
   field descriptions.
4. Add in-memory protocol coverage plus a PostgreSQL-backed integration path.
   Playwright applies only when the SPA workflow also changes.
5. Keep the documented tool count and scope in `README.md` synchronized.
