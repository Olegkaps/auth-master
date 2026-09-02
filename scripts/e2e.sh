#!/usr/bin/env bash
# =============================================================================
# Run Playwright E2E with one command (make test-e2e):
#   1. start PostgreSQL and Mailpit through Compose;
#   2. run the backend with a short access-token TTL;
#   3. run Playwright with its actionable list reporter;
#   4. use and remove an isolated database, then stop the backend on exit.
#
# Arguments are forwarded to Playwright, for example: ./scripts/e2e.sh extra.spec.ts
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE="${COMPOSE:-$(command -v podman >/dev/null 2>&1 && echo 'podman compose' || echo 'docker compose')}"
ACCESS_TTL_SEC="${E2E_ACCESS_TTL_SEC:-20}"
REGISTRATION_OPEN="${E2E_REGISTRATION_OPEN:-false}"
SKIP_LOGIN_OTP="${E2E_SKIP_LOGIN_OTP:-false}"
ADMIN_LOGIN="${E2E_ADMIN_LOGIN:-admin}"
ADMIN_EMAIL="${E2E_ADMIN_EMAIL:-admin@localhost}"
ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-Adm1n!Passw0rd123}"

echo "==> infrastructure: PostgreSQL + Mailpit"
$COMPOSE up -d postgres mailpit
# The E2E runner owns port 8080. Stop a production stack left by make up so the
# freshly built binary cannot silently lose the bind race to stale code.
$COMPOSE stop web authd >/dev/null 2>&1 || true

echo "==> waiting for PostgreSQL"
for _ in $(seq 1 30); do
  if $COMPOSE exec -T postgres pg_isready -U auth -d auth >/dev/null 2>&1; then break; fi
  sleep 1
done

BACKEND_PID=""
BACKEND_LOG="$(mktemp -t authd-e2e.XXXXXX.log)"
BACKEND_BIN=""
E2E_DB="auth_e2e"
E2E_SECRET_DIR="$(mktemp -d -t authd-e2e-secrets.XXXXXX)"
DATABASE_URL_FILE="$E2E_SECRET_DIR/database-url"
BOOTSTRAP_PASSWORD_FILE="$E2E_SECRET_DIR/bootstrap-password"
HISTORY_KEY_FILE="$E2E_SECRET_DIR/history-key"
SIGNING_KEY_FILE="$E2E_SECRET_DIR/signing-key"
INVITE_CALLBACK_FILE="$E2E_SECRET_DIR/invite-callback"
MAGIC_CALLBACK_FILE="$E2E_SECRET_DIR/magic-callback"
printf '%s' "postgres://auth:auth@localhost:5432/${E2E_DB}?sslmode=disable" >"$DATABASE_URL_FILE"
printf '%s' "$ADMIN_PASSWORD" >"$BOOTSTRAP_PASSWORD_FILE"
printf '%s' '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' >"$HISTORY_KEY_FILE"
printf '%s' '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' >"$SIGNING_KEY_FILE"
printf '%s' 'http://localhost:5173/#/register' >"$INVITE_CALLBACK_FILE"
printf '%s' 'http://localhost:5173/#/magic' >"$MAGIC_CALLBACK_FILE"
cleanup() {
  [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
  $COMPOSE exec -T postgres dropdb -U auth --if-exists --force "$E2E_DB" >/dev/null 2>&1 || true
	[ -n "$BACKEND_BIN" ] && rm -f "$BACKEND_BIN"
	rm -f "$BACKEND_LOG"
	rm -f "$DATABASE_URL_FILE" "$BOOTSTRAP_PASSWORD_FILE" "$HISTORY_KEY_FILE" "$SIGNING_KEY_FILE" "$INVITE_CALLBACK_FILE" "$MAGIC_CALLBACK_FILE"
  rmdir "$E2E_SECRET_DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> reset isolated E2E database"
$COMPOSE exec -T postgres dropdb -U auth --if-exists --force "$E2E_DB"
$COMPOSE exec -T postgres createdb -U auth "$E2E_DB"

# Build and run a binary directly. With go run, the child process can survive
# its parent and keep stdout open. Store backend logs separately so make prints
# only the Playwright summary.
echo "==> building backend"
BACKEND_BIN="$(mktemp -t authd-e2e.XXXXXX)"
go build -o "$BACKEND_BIN" ./cmd/authd

echo "==> backend (ACCESS_TOKEN_TTL=${ACCESS_TTL_SEC}s, logs: $BACKEND_LOG)"
env -u DATABASE_URL -u BOOTSTRAP_SUPERUSER_PASSWORD -u PASSWORD_HISTORY_ENCRYPTION_KEY -u SIGNING_KEY_MASTER_KEY -u REGISTRATION_INVITE_CALLBACK_URL -u MAGIC_LINK_CALLBACK_URL \
DATABASE_URL_FILE="$DATABASE_URL_FILE" \
SMTP_HOST=localhost SMTP_PORT=1025 \
ACCESS_TOKEN_TTL="${ACCESS_TTL_SEC}s" \
REGISTRATION_OPEN="$REGISTRATION_OPEN" \
SKIP_LOGIN_OTP="$SKIP_LOGIN_OTP" \
OTP_MAX_ATTEMPTS=3 \
OTP_RESET_MIN_INTERVAL=0s \
BOOTSTRAP_SUPERUSER_LOGIN="$ADMIN_LOGIN" \
BOOTSTRAP_SUPERUSER_EMAIL="$ADMIN_EMAIL" \
BOOTSTRAP_SUPERUSER_PASSWORD_FILE="$BOOTSTRAP_PASSWORD_FILE" \
PASSWORD_HISTORY_ENCRYPTION_KEY_FILE="$HISTORY_KEY_FILE" \
SIGNING_KEY_MASTER_KEY_FILE="$SIGNING_KEY_FILE" \
REGISTRATION_INVITE_CALLBACK_URL_FILE="$INVITE_CALLBACK_FILE" \
MAGIC_LINK_CALLBACK_URL_FILE="$MAGIC_CALLBACK_FILE" \
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
