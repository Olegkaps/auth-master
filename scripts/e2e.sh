#!/usr/bin/env bash
# =============================================================================
# Run Playwright E2E with one command (make test-e2e):
#   1. start PostgreSQL and Mailpit through Compose;
#   2. run the backend with a short access-token TTL;
#   3. run Playwright with its actionable list reporter;
#   4. stop the backend on exit.
#
# Arguments are forwarded to Playwright, for example: ./scripts/e2e.sh extra.spec.ts
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE="${COMPOSE:-$(command -v podman >/dev/null 2>&1 && echo 'podman compose' || echo 'docker compose')}"
ACCESS_TTL_SEC="${E2E_ACCESS_TTL_SEC:-20}"
ADMIN_LOGIN="${E2E_ADMIN_LOGIN:-admin}"
ADMIN_EMAIL="${E2E_ADMIN_EMAIL:-admin@localhost}"
ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-Adm1n!Passw0rd123}"

echo "==> infrastructure: PostgreSQL + Mailpit"
$COMPOSE up -d postgres mailpit
# The E2E runner owns port 8080. Stop a Compose-managed backend left by make up
# so the freshly built binary cannot silently lose the bind race to stale code.
$COMPOSE stop authd >/dev/null 2>&1 || true

echo "==> waiting for PostgreSQL"
for _ in $(seq 1 30); do
  if $COMPOSE exec -T postgres pg_isready -U auth -d auth >/dev/null 2>&1; then break; fi
  sleep 1
done

BACKEND_PID=""
BACKEND_LOG="$(mktemp -t authd-e2e.XXXXXX.log)"
cleanup() { [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true; }
trap cleanup EXIT

# Build and run a binary directly. With go run, the child process can survive
# its parent and keep stdout open. Store backend logs separately so make prints
# only the Playwright summary.
echo "==> building backend"
BACKEND_BIN="$(mktemp -t authd-e2e.XXXXXX)"
go build -o "$BACKEND_BIN" ./cmd/authd

echo "==> backend (ACCESS_TOKEN_TTL=${ACCESS_TTL_SEC}s, logs: $BACKEND_LOG)"
DATABASE_URL="postgres://auth:auth@localhost:5432/auth?sslmode=disable" \
SMTP_HOST=localhost SMTP_PORT=1025 \
ACCESS_TOKEN_TTL="${ACCESS_TTL_SEC}s" \
BOOTSTRAP_SUPERUSER_LOGIN="$ADMIN_LOGIN" \
BOOTSTRAP_SUPERUSER_EMAIL="$ADMIN_EMAIL" \
BOOTSTRAP_SUPERUSER_PASSWORD="$ADMIN_PASSWORD" \
"$BACKEND_BIN" >"$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!

echo "==> waiting for backend on :8080"
for _ in $(seq 1 60); do
  if curl -sf http://localhost:8080/healthz >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "==> Playwright"
cd web
[ -d node_modules ] || npm ci --no-audit
E2E_ACCESS_TTL_SEC="$ACCESS_TTL_SEC" \
E2E_ADMIN_LOGIN="$ADMIN_LOGIN" \
E2E_ADMIN_EMAIL="$ADMIN_EMAIL" \
E2E_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
npx playwright test "$@"
