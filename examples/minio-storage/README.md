# MinIO storage workspace

This example combines private MinIO objects with auth-master folder roles,
capability tags, inherited group sharing, and a browser file workspace. MinIO
has no host port; every list, upload, and download passes through this service.

## First use

Start the isolated, seeded stack:

```sh
make -C examples up EXAMPLE=minio-storage
```

Open `http://127.0.0.1:8191`. The command also prints the auth and Mailpit URLs,
demo personas, token command, and reset command. Obtain a fresh human token and
paste it into the workspace:

```sh
make -C examples token EXAMPLE=minio-storage PERSONA=owner
```

The seeded personas demonstrate distinct boundaries:

- `storage-owner` owns the whole tree.
- `storage-reader` can list and download from the shared child folder.
- `storage-writer` can upload to that child folder.
- `storage-admin` can create and share descendants there.
- `storage-stranger` cannot enter the tree.

Tokens are intentionally short-lived. If a request reports an expired or
invalid token, rerun the token command and paste the replacement. The page has
no login form and never stores the token.

## Folder and access model

Registration provisions `storage.folder.<user-uuid>` with `read`, `write`, and
`admin` tags and grants the owner `role_admin`. Every child folder gets a
deterministic role derived from its canonical path and mounted below its direct
parent. Object checks use the role for the file's containing folder.

A `storage.group.<name>` role can be mounted as a parent of a selected folder.
Group members inherit their granted tags into that folder and its descendants,
not into an ancestor or sibling. The Access panel lists direct group shares for
the selected folder.

Paths are bounded canonical relative paths: no absolute paths, backslashes,
empty segments, `.` or `..`. Listings return immediate children, hide `.keep`
markers, and sort folders before files. Uploads require `Content-Length` and are
limited to 16 MiB.

## Public registration and privileged provisioning

The public form accepts only `login`, `email`, and `password`. The backend mints
a short-lived service JWT from `AUTH_SERVICE_LOGIN` and `AUTH_SERVICE_SECRET`,
creates a one-time invite, registers the human, provisions the root role, and
discards the JWT. A complete result is `201`. If registration succeeded but
post-registration provisioning failed, the response is `202` with a retry URL;
only user IDs held in the process's pending-registration set can use that public
retry.

Folder creation follows the same rule: authorize the human against the parent
folder, mint one service JWT, create/tag/mount the child role, create its MinIO
marker, and discard the JWT. Service credentials and JWTs are never written to
disk, logged, or returned.

{% note warning %}

This deliberately powerful bootstrap service is for the disposable demo stack.
A production system should use a narrowly scoped workload identity, protect
public registration with rate limits and abuse controls, and add an idempotency
or durable provisioning workflow instead of relying on process memory.

{% endnote %}

## Data and reset

The example uses disposable PostgreSQL and MinIO storage. Seeding is
idempotent: rerunning it reconciles missing roles, memberships, shares, and demo
objects without overwriting user-edited files. Reset the complete stack with:

```sh
make -C examples reset EXAMPLE=minio-storage
```

Run automated checks only through the nested Makefile:

```sh
make -C examples test-unit
make -C examples test-integration
make -C examples test-e2e
```
