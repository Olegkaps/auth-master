# =============================================================================
# auth-master — Makefile
# =============================================================================
# Обязательная проверка бэкенда перед merge: линтеры + тесты на хосте, затем
# интеграция и covgate в контейнере:
#   make check && make compose-test-integration
#   # или: podman compose -f docker-compose.test.yml run --rm test-integration
# =============================================================================

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# --- Compose (Docker по умолчанию; для Podman: make … COMPOSE='podman compose') ---
COMPOSE         ?= docker compose
COMPOSE_FILE    ?= docker-compose.test.yml
COMPOSE_PROJECT ?=
COMPOSE_RUN      = $(COMPOSE) $(if $(COMPOSE_PROJECT),-p $(COMPOSE_PROJECT),) -f $(COMPOSE_FILE) run --rm

# --- Go / lint ---
GOLANGCI_LINT_VER ?= v1.64.5
GO_PACKAGES       ?= ./...

# Go файлы для gofmt -check (без web/, vendor).
GOFMT_PATHS := $(shell find cmd internal tools -name '*.go' 2>/dev/null | sort)

.PHONY: help
.DEFAULT_GOAL := help

help: ## Показать цели
	@echo "Host (локальный Go)"
	@echo "  make fmt            gofmt -w cmd internal tools"
	@echo "  make fmt-check      проверка форматирования"
	@echo "  make vet            go vet"
	@echo "  make lint / lint-go  golangci-lint (нужен бинарь или см. lint-go-install)"
	@echo "  make test           go test ./... -count=1"
	@echo "  make test-race      go test -race ./... -count=1"
	@echo "  make test-integration  covgate на хосте (Testcontainers / INTEGRATION_DATABASE_URL)"
	@echo "  make coverage       coverprofile + go tool cover"
	@echo "  make check          fmt-check + lint-go + test"
	@echo ""
	@echo "Compose (интеграция + covgate в контейнере — обязательно при изменениях бэкенда)"
	@echo "  make compose-test              сервис test (нужен PODMAN_SOCKET, см. docker-compose.test.yml)"
	@echo "  make compose-test-integration  Postgres + полный go test + covgate"
	@echo "  make compose-test-coverage     покрытие в контейнере"
	@echo "  Переопределение: make compose-test-integration COMPOSE='podman compose'"
	@echo ""
	@echo "Алиасы: docker-test-integration, podman-test-integration, podman-test (с авто-сокетом)"
	@echo ""
	@echo "Прочее: run, swagger, web-*"

# -----------------------------------------------------------------------------
# Форматирование и базовые проверки
# -----------------------------------------------------------------------------

fmt: ## gofmt -w исходников Go (cmd, internal, tools)
	@gofmt -w $(GOFMT_PATHS)

fmt-check: ## Сбой, если файлы не отформатированы
	@if [ -z "$(GOFMT_PATHS)" ]; then echo "no Go files under cmd/internal/tools"; exit 1; fi
	@out=$$(gofmt -l $(GOFMT_PATHS)); if [ -n "$$out" ]; then echo "$$out"; exit 1; fi

vet: ## go vet
	go vet $(GO_PACKAGES)

# -----------------------------------------------------------------------------
# Линтеры (Go)
# -----------------------------------------------------------------------------

lint: lint-go ## Все линтеры (сейчас: Go)

lint-go: ## golangci-lint run
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo >&2 "golangci-lint not found. Install: make lint-go-install"; \
		exit 1; \
	}
	golangci-lint run $(GO_PACKAGES)

lint-go-install: ## Установить golangci-lint в GOPATH/bin
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VER)

lint-go-run: ## Запуск линтера без установки (медленнее, через go run)
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VER) run $(GO_PACKAGES)

# -----------------------------------------------------------------------------
# Тесты на хосте
# -----------------------------------------------------------------------------

test: ## unit + интеграционные тесты (как получится на хосте)
	go test $(GO_PACKAGES) -count=1

test-race: ## go test -race
	go test $(GO_PACKAGES) -count=1 -race

test-integration: ## covgate (требует Docker/Podman или INTEGRATION_DATABASE_URL)
	go test -tags=covgate ./internal/covgate -count=1

coverage: ## coverprofile в корне
	go test $(GO_PACKAGES) -count=1 -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -8

# -----------------------------------------------------------------------------
# Compose: Docker или Podman (один интерфейс COMPOSE)
# -----------------------------------------------------------------------------

compose-test: ## Сервис test (Testcontainers внутри контейнера; нужен PODMAN_SOCKET)
	@test -n "$${PODMAN_SOCKET:-}" || { echo >&2 "export PODMAN_SOCKET=/var/run/docker.sock  # или сокет Podman"; exit 1; }
	$(COMPOSE_RUN) test

compose-test-integration: ## Postgres + go test + covgate (обязательно для изменений бэкенда)
	$(COMPOSE_RUN) test-integration

compose-test-coverage: ## Покрытие как в CI-образе
	$(COMPOSE_RUN) test-coverage

docker-test-integration: ## То же, что compose-test-integration с docker compose
	@$(MAKE) compose-test-integration COMPOSE='docker compose'

docker-test: ## compose-test с docker compose (задайте PODMAN_SOCKET=/var/run/docker.sock при Docker Engine)
	@$(MAKE) compose-test COMPOSE='docker compose'

podman-test-integration: ## compose-test-integration с podman compose
	@$(MAKE) compose-test-integration COMPOSE='podman compose'

podman-test-coverage: ## compose-test-coverage с podman compose
	@$(MAKE) compose-test-coverage COMPOSE='podman compose'

podman-test: ## test + автоподстановка PODMAN_SOCKET для Podman
	@command -v podman >/dev/null 2>&1 || { echo >&2 "podman: not in PATH"; exit 1; }
	@sock="$${PODMAN_SOCKET:-}"; \
	[ -n "$$sock" ] || sock=$$(podman info -f '{{.Host.RemoteSocket.Path}}' 2>/dev/null || true); \
	sock=$$(echo "$$sock" | sed 's|^unix://||'); \
	[ -n "$$sock" ] || { echo >&2 "podman-test: set PODMAN_SOCKET or ensure podman info works"; exit 1; }; \
	export PODMAN_SOCKET="$$sock"; \
	$(MAKE) compose-test COMPOSE='podman compose'

# -----------------------------------------------------------------------------
# Агрегаты
# -----------------------------------------------------------------------------

check: fmt-check lint-go test ## Локальная проверка (lint включает govet; при необходимости: make vet)

check-backend: check compose-test-integration ## Локально + интеграция в Compose (полный бэкенд-цикл)

# -----------------------------------------------------------------------------
# Приложение и фронт
# -----------------------------------------------------------------------------

run: ## go run ./cmd/authd
	go run ./cmd/authd

swagger: ## OpenAPI (docs/docs.go, swagger.json, swagger.yaml)
	go run github.com/swaggo/swag/cmd/swag@v1.16.4 init -g cmd/authd/main.go -o docs --parseInternal

web-install:
	@command -v npm >/dev/null 2>&1 || { echo >&2 "npm: not in PATH, skip web-install"; exit 0; }
	cd web && npm ci --no-audit

web-dev:
	@command -v npm >/dev/null 2>&1 || { echo >&2 "npm: not in PATH, skip web-dev"; exit 0; }
	cd web && npm run dev

web-preview:
	@command -v npm >/dev/null 2>&1 || { echo >&2 "npm: not in PATH, skip web-preview"; exit 0; }
	cd web && npm run preview

web-build:
	@command -v npm >/dev/null 2>&1 || { echo >&2 "npm: not in PATH, skip web-build"; exit 0; }
	cd web && npm ci --no-audit && npm run build
