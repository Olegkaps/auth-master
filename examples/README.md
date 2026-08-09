# External-service examples

Exactly three examples show three different integration patterns:

- [`minio-storage`](minio-storage/) — gRPC provisioning, role tags, inherited
  group access, and a private object store.
- [`deployment-api`](deployment-api/) — stateless HTTP role checks for a
  deployment service.
- [`support-desk`](support-desk/) — gRPC token verification and central support
  roles layered over local ticket ownership.

The examples are a nested module and do not affect auth-master's module graph or
production image. Install and run their independent test matrix with:

```sh
make -C examples install
make -C examples test
```

Each service has its own isolated Compose stack and browser UI. Start a complete,
seeded demo from the repository root:

```sh
make -C examples up EXAMPLE=deployment-api
```

`up` selects Podman or Docker Compose, waits for the application, reconciles
demo users, roles, and data through public contracts, and prints the app, auth,
and Mailpit URLs. Application ports default to 8191, 8192, and 8193; auth uses
8291, 8292, and 8293; Mailpit uses 8391, 8392, and 8393.

The pages deliberately retain bearer-token inputs to show the human token
crossing the service boundary. Print a fresh real human token for a seeded
persona with:

```sh
make -C examples token EXAMPLE=deployment-api PERSONA=developer
```

Run `make -C examples seed EXAMPLE=deployment-api` to safely reconcile missing
fixtures. It does not replace existing storage files or duplicate seeded
tickets. `down EXAMPLE=deployment-api` removes the disposable stack; `reset`
removes and recreates it. All demo accounts use `Example!Passw0rd9`; never copy
these local-only credentials into a deployed environment.

`make -C examples test-integration` runs a separate full-stack contract for
each deployment: storage traverses auth-master and the application before
reaching private MinIO, deployment checks a real allowed and denied role, and
support traverses the HTTP adapter, gRPC service, auth-master, and local ticket
ownership. `make -C examples test-e2e` retains the rendered browser journeys.
Test targets tear down their disposable stacks and volumes; unlike `up`, they do
not prepare a stack for manual exploration.

The support example documents one deliberate fail-closed boundary: auth-master
currently returns the same gRPC `Internal` status for a structurally valid
tampered JWT and for authentication repository or key failures. The example
therefore renders sanitized `503 Unavailable` for that ambiguous result while
returning `401 Unauthenticated` for missing or syntactically malformed tokens.
