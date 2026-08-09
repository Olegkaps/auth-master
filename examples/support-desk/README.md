# Support desk (gRPC plus local ownership)

This example exposes `examples.support.v1.SupportService` over gRPC using
protobuf `Struct` messages to keep the sample compact. Every request carries an
`access_token` field and auth-master verifies it before local state is read.

## Role model

- A ticket owner can read their own ticket from local ownership data.
- `support.agent` can read any ticket.
- `support.admin` can read any ticket and is the natural role for later
  management operations.

Start a complete seeded stack from the repository root:

```sh
make -C examples up EXAMPLE=support-desk
```

The command creates owner, stranger, agent, and administrator personas plus one
owner ticket. All accounts use `Example!Passw0rd9`. Print a fresh token with:

```sh
make -C examples token EXAMPLE=support-desk PERSONA=agent
```

The UI is at `http://127.0.0.1:8193`, auth-master at
`http://127.0.0.1:8293`, and Mailpit at `http://127.0.0.1:8393`. The UI calls a
local HTTP adapter, which invokes the example's real gRPC service; the service
then verifies the human access token with auth-master before reading ticket
state. A seeded ticket is selected automatically, and creating a ticket selects
the returned UUID so no JSON copying is required.

`make -C examples seed EXAMPLE=support-desk` is idempotent while the app is
running. Tickets are intentionally in memory, so restarting the app requires
running `seed` again. `reset EXAMPLE=support-desk` recreates the disposable
stack. Test targets tear their stacks down on completion.

## Fail-closed token errors

The HTTP adapter returns `401 Unauthenticated` for a missing token or a token
that is not even a compact JWT. A structurally valid token with a tampered
signature returns sanitized `503 Unavailable`, and the service still does not
inspect local ticket state. The rendered page translates those transport
statuses into session-expired and dependency-unavailable guidance.

This distinction is intentionally conservative. The current auth-master gRPC
contract reports both raw JWT credential failures and repository or key
decryption failures as the same `Internal` status. The isolated example cannot
tell those cases apart, so it treats the ambiguous status as an authentication
dependency outage and fails closed. Returning `401` for it would mask a real
outage. Resolving the ambiguity requires typed errors in the root gRPC contract
or an asymmetric verification contract such as JWKS; both are outside this
root-isolated example.

Reflection is intentionally not enabled. The in-memory store is for
demonstration only; production persistence must enforce the same ownership rule
transactionally.
