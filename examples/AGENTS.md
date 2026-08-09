# AGENTS.md — examples

These programs demonstrate how separate services consume auth-master. Keep them
small, runnable, and semantically distinct; shared authorization transports
belong in `internal/authz`.

## Boundaries

- `minio-storage` demonstrates gRPC provisioning and per-request authorization
  for resources represented by auth-master roles and tags.
- `deployment-api` demonstrates HTTP authorization checks for global,
  occupational, and resource-scoped service roles.
- `support-desk` demonstrates gRPC token verification and coarse central roles
  combined with local resource ownership.
- Do not add parallel HTTP and gRPC editions of the same example.

## Security

Always pass the human caller's short-lived access token to auth-master for
resource authorization and let auth-master derive its subject. Never accept a
caller-supplied subject and never persist a human access token. Apply deadlines
to outbound calls and authorize every request without caching. HTTP clients
must reject redirects when the request body contains a token.

Demo seeders and storage provisioning use the configured bootstrap superuser
service credentials to mint a fresh short-lived service JWT for each bounded
privileged action, then discard it. Never persist, return, or log the JWT or
service secret. Service actors are limited to Admin and Role operations;
Identity, Session, and body-token role checks remain human-only.

Validate bounded input at the edge. JSON endpoints reject unknown fields and
trailing values. Object paths must remain below the selected user prefix. MinIO
stays private behind the storage service.

Storage folder paths are canonical relative paths. Every folder has a
deterministic role mounted below its canonical parent. File authorization checks
the containing folder role, and sharing mounts only the selected folder below a
group so access inherits to descendants but not ancestors or siblings.

## Testing

The directory is an independent Go and browser project. Invoke all checks from
here through `make`; never run Go, Playwright, or Compose test commands directly.
`make test-unit` covers decisions and wire adapters, `make test-integration`
uses each example's isolated Compose stack, and `make test-e2e` drives the
rendered pages through stable `data-testid` controls.

Each example owns its Compose project, tmpfs PostgreSQL, Mailpit, authd, and
application. MinIO exists only in the storage stack and has no host port. Keep
the root module, Dockerfile, and normal Compose stack free of example runtime
dependencies.
