# =============================================================================
# auth-master — Makefile
# =============================================================================
# Run everything through make. Individual groups and the full suite:
#
#   make test-unit          fast Go tests without a database
#   make test-integration   Go integration tests and coverage gate
#   make test-e2e           Playwright UI tests with a managed stack
#   make test               all groups with a final failure summary
#
# Start the project: make install, then make up (or make dev for local work).
# =============================================================================

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# --- Compose: prefer Podman, otherwise Docker --------------------------------
COMPOSE ?= $(shell command -v podman >/dev/null 2>&1 && echo 'podman compose' || echo 'docker compose')

# --- Pinned tool versions ----------------------------------------------------
GOLANGCI_LINT_VER ?= v2.10.1
SWAG_VER          ?= v1.16.4
GOTESTSUM_VER     ?= v1.13.0
PLAYWRIGHT_INSTALL ?= npx playwright install chromium

# gotestsum prints an actionable summary. Use PATH or run the pinned module.
GOTESTSUM = $(shell command -v gotestsum 2>/dev/null || echo 'go run gotest.tools/gotestsum@$(GOTESTSUM_VER)')
TESTSUM   = $(GOTESTSUM) --format testname --

GOFMT_PATHS := $(shell find cmd internal tools -name '*.go' 2>/dev/null | sort)

.PHONY: help install env-file \
	up down logs run dev web-dev \
	test test-unit test-integration test-e2e test-race \
	test-fuzz web-build docker-build \
	fmt fmt-check vet lint lint-go lint-ts check swagger

help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# Compose requires env_file even when every relevant value has a default. Keep
# developer overrides intact and bootstrap only a missing, ignored .env file.
.env:
	cp .env.example .env

env-file: .env ## Create .env from .env.example when it is missing

# -----------------------------------------------------------------------------
# Install everything with one command
# -----------------------------------------------------------------------------

install: ## Install Go tools, web dependencies, and Playwright
	go mod download
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VER)
	go install github.com/swaggo/swag/cmd/swag@$(SWAG_VER)
	go install gotest.tools/gotestsum@$(GOTESTSUM_VER)
	@command -v npm >/dev/null 2>&1 && { cd web && npm ci --no-audit && $(PLAYWRIGHT_INSTALL); } \
		|| echo "npm not found — skipping web dependencies"

# -----------------------------------------------------------------------------
# Run the project
# -----------------------------------------------------------------------------

up: | .env
up: ## Start PostgreSQL, Mailpit, and authd through Compose
	$(COMPOSE) up --build -d
	@echo "authd: http://localhost:8080   swagger: http://localhost:8080/swagger/   mailpit: http://localhost:8025"

down: | .env
down: ## Stop the stack
	$(COMPOSE) down

logs: | .env
logs: ## Follow stack logs
	$(COMPOSE) logs -f

dev: | .env
dev: ## Start infrastructure and run the backend locally
	$(COMPOSE) up -d postgres mailpit
	DATABASE_URL=postgres://auth:auth@localhost:5432/auth?sslmode=disable \
	SMTP_HOST=localhost SMTP_PORT=1025 \
	BOOTSTRAP_SUPERUSER_LOGIN=admin BOOTSTRAP_SUPERUSER_EMAIL=admin@localhost \
	BOOTSTRAP_SUPERUSER_PASSWORD='Adm1n!Passw0rd123' \
	go run ./cmd/authd

run: dev ## Alias for make dev

web-dev: ## Start the Vite SPA server on port 5173
	cd web && npm run dev

# -----------------------------------------------------------------------------
# Test groups and full suite
# -----------------------------------------------------------------------------

test-unit: ## Run fast Go tests without a database
	SKIP_TESTCONTAINERS=1 $(TESTSUM) ./... -count=1

# Start PostgreSQL through Compose. Tests create ephemeral databases on it.
# REQUIRE_COVERAGE_GATE=1 makes an unavailable database fail the coverage gate.
INTEGRATION_DB_URL ?= postgres://auth:auth@localhost:5432/auth?sslmode=disable

test-integration: | .env
test-integration: ## Run Go integration tests and the coverage gate
	$(COMPOSE) up -d postgres mailpit
	@echo "==> waiting for PostgreSQL"; \
	for _ in $$(seq 1 30); do \
		$(COMPOSE) exec -T postgres pg_isready -U auth -d auth >/dev/null 2>&1 && break; sleep 1; \
	done
	INTEGRATION_DATABASE_URL='$(INTEGRATION_DB_URL)' REQUIRE_COVERAGE_GATE=1 $(TESTSUM) ./... -count=1
	INTEGRATION_DATABASE_URL='$(INTEGRATION_DB_URL)' REQUIRE_COVERAGE_GATE=1 $(TESTSUM) -tags=covgate ./internal/covgate -count=1

test-e2e: | .env
test-e2e: ## Run Playwright UI tests against a managed stack
	./scripts/e2e.sh $(E2E_ARGS)

# Run every group even when an earlier group fails, then print a summary.
test: ## Run lint, race, fuzz, integration, and E2E with a summary
	@fails=""; \
	$(MAKE) --no-print-directory lint             || fails="$$fails lint"; \
	$(MAKE) --no-print-directory test-race        || fails="$$fails race"; \
	$(MAKE) --no-print-directory test-fuzz        || fails="$$fails fuzz"; \
	$(MAKE) --no-print-directory test-integration || fails="$$fails integration"; \
	$(MAKE) --no-print-directory test-e2e         || fails="$$fails e2e"; \
	echo; echo "==================== SUMMARY ===================="; \
	if [ -z "$$fails" ]; then echo "✅ all groups passed"; \
	else echo "❌ failed groups:$$fails (details are shown above)"; exit 1; fi

test-race: ## Run Go unit tests with the race detector
	SKIP_TESTCONTAINERS=1 $(TESTSUM) -race ./... -count=1

test-fuzz: ## Run the short deterministic CI fuzz smoke tests
	go test ./internal/crypto -run='^$$' -fuzz=FuzzLevenshtein -fuzztime=3s
	go test ./internal/jwtutil -run='^$$' -fuzz=FuzzParseUnverifiedClaims -fuzztime=3s

# -----------------------------------------------------------------------------
# Production builds
# -----------------------------------------------------------------------------

web-build: ## Build the production SPA bundle
	cd web && npm run build

docker-build: | .env
docker-build: ## Build the production authd container image through Compose
	$(COMPOSE) build authd

# -----------------------------------------------------------------------------
# Lint and format checks
# -----------------------------------------------------------------------------

lint: fmt-check vet lint-go lint-ts ## Run all Go and TypeScript checks

fmt: ## gofmt -w
	@gofmt -w $(GOFMT_PATHS)

fmt-check: ## Fail when Go code is not formatted
	@out=$$(gofmt -l $(GOFMT_PATHS)); if [ -n "$$out" ]; then echo "not formatted:"; echo "$$out"; exit 1; fi

vet: ## go vet
	go vet ./...

lint-go: ## Run golangci-lint
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not found — run make install"; exit 1; }
	golangci-lint run ./...

lint-ts: ## Run ESLint and TypeScript checks for web/
	@command -v npm >/dev/null 2>&1 || { echo "npm not found — skipping TypeScript lint"; exit 0; }
	cd web && npm run lint

check: lint test-integration ## Run the fast pre-merge gate without E2E

# -----------------------------------------------------------------------------
# Swagger
# -----------------------------------------------------------------------------

swagger: ## Regenerate OpenAPI artifacts in docs/
	go run github.com/swaggo/swag/cmd/swag@$(SWAG_VER) init -g cmd/authd/main.go -o docs --parseInternal
