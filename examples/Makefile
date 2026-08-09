SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

COMPOSE ?= $(shell command -v podman >/dev/null 2>&1 && echo 'podman compose' || echo 'docker compose')
GOTESTSUM_VER ?= v1.13.0
TESTSUM = go run gotest.tools/gotestsum@$(GOTESTSUM_VER) --format testname --
GOFILES := $(shell find . -name '*.go' -not -path './vendor/*' | sort)
EXAMPLES := minio-storage deployment-api support-desk
MINIO_STORAGE_PORT ?= 8191
DEPLOYMENT_API_PORT ?= 8192
SUPPORT_DESK_PORT ?= 8193
MINIO_AUTH_PORT ?= 8291
DEPLOYMENT_AUTH_PORT ?= 8292
SUPPORT_AUTH_PORT ?= 8293
MINIO_MAILPIT_PORT ?= 8391
DEPLOYMENT_MAILPIT_PORT ?= 8392
SUPPORT_MAILPIT_PORT ?= 8393
export MINIO_STORAGE_PORT DEPLOYMENT_API_PORT SUPPORT_DESK_PORT
export MINIO_AUTH_PORT DEPLOYMENT_AUTH_PORT SUPPORT_AUTH_PORT
export MINIO_MAILPIT_PORT DEPLOYMENT_MAILPIT_PORT SUPPORT_MAILPIT_PORT

.PHONY: install fmt lint compose-check up seed token down reset test-unit test-race test-integration test-e2e test

install:
	go mod download
	npm ci --no-audit
	npx playwright install chromium

fmt:
	gofmt -w $(GOFILES)

lint:
	@out=$$(gofmt -l $(GOFILES)); test -z "$$out" || { echo "not formatted:"; echo "$$out"; exit 1; }
	go vet ./...
	go build ./...

compose-check:
	@for example in $(EXAMPLES); do \
		$(COMPOSE) -p "auth-master-$$example" -f "$$example/docker-compose.yml" config >/dev/null || exit $$?; \
		echo "PASS $$example Compose renders with isolated configurable ports"; \
	done

up:
	@test -n "$(EXAMPLE)" || { echo "EXAMPLE is required: minio-storage, deployment-api, or support-desk"; exit 2; }; \
	case " $(EXAMPLES) " in *" $(EXAMPLE) "*) ;; *) echo "unsupported EXAMPLE=$(EXAMPLE)"; exit 2 ;; esac; \
	project="auth-master-$(EXAMPLE)"; file="$(EXAMPLE)/docker-compose.yml"; \
	$(COMPOSE) -p "$$project" -f "$$file" up -d --build; \
	$(COMPOSE) -p "$$project" -f "$$file" --profile seed run --rm seed; \
	case "$(EXAMPLE)" in minio-storage) app_port='$(MINIO_STORAGE_PORT)'; auth_port='$(MINIO_AUTH_PORT)'; mail_port='$(MINIO_MAILPIT_PORT)' ;; deployment-api) app_port='$(DEPLOYMENT_API_PORT)'; auth_port='$(DEPLOYMENT_AUTH_PORT)'; mail_port='$(DEPLOYMENT_MAILPIT_PORT)' ;; support-desk) app_port='$(SUPPORT_DESK_PORT)'; auth_port='$(SUPPORT_AUTH_PORT)'; mail_port='$(SUPPORT_MAILPIT_PORT)' ;; esac; \
	ready=0; for _ in $$(seq 1 60); do curl -fsS "http://127.0.0.1:$$app_port/" >/dev/null 2>&1 && { ready=1; break; }; sleep 1; done; \
	test "$$ready" = 1 || { echo "readiness timeout: http://127.0.0.1:$$app_port/"; exit 1; }; \
	echo "READY $(EXAMPLE) app=http://127.0.0.1:$$app_port auth=http://127.0.0.1:$$auth_port mailpit=http://127.0.0.1:$$mail_port"; \
	$(COMPOSE) -p "$$project" -f "$$file" --profile seed run --rm --no-deps seed personas; \
	echo "Fresh token: make -C examples token EXAMPLE=$(EXAMPLE) PERSONA=<key>"; \
	echo "Reset: make -C examples reset EXAMPLE=$(EXAMPLE)"

seed:
	@test -n "$(EXAMPLE)" || { echo "EXAMPLE is required"; exit 2; }; \
	case " $(EXAMPLES) " in *" $(EXAMPLE) "*) ;; *) echo "unsupported EXAMPLE=$(EXAMPLE)"; exit 2 ;; esac; \
	$(COMPOSE) -p "auth-master-$(EXAMPLE)" -f "$(EXAMPLE)/docker-compose.yml" --profile seed run --rm seed

token:
	@test -n "$(EXAMPLE)" || { echo "EXAMPLE is required"; exit 2; }; \
	test -n "$(PERSONA)" || { echo "PERSONA is required; run make -C examples up EXAMPLE=$(EXAMPLE) to list keys"; exit 2; }; \
	case " $(EXAMPLES) " in *" $(EXAMPLE) "*) ;; *) echo "unsupported EXAMPLE=$(EXAMPLE)"; exit 2 ;; esac; \
	$(COMPOSE) -p "auth-master-$(EXAMPLE)" -f "$(EXAMPLE)/docker-compose.yml" --profile seed run --rm --no-deps -e PERSONA="$(PERSONA)" seed token

test-unit:
	$(TESTSUM) ./... -count=1

test-race:
	$(TESTSUM) -race ./... -count=1

test-integration: compose-check
	@for example in $(EXAMPLES); do \
		echo "==> $$example integration"; \
		trap '$(COMPOSE) -p "auth-master-'"$$example"'" -f "'"$$example"'/docker-compose.yml" down -v' EXIT; \
		$(COMPOSE) -p "auth-master-$$example" -f "$$example/docker-compose.yml" up -d --build || exit $$?; \
		case "$$example" in \
			minio-storage) app_port='$(MINIO_STORAGE_PORT)'; auth_port='$(MINIO_AUTH_PORT)'; mail_port='$(MINIO_MAILPIT_PORT)' ;; \
			deployment-api) app_port='$(DEPLOYMENT_API_PORT)'; auth_port='$(DEPLOYMENT_AUTH_PORT)'; mail_port='$(DEPLOYMENT_MAILPIT_PORT)' ;; \
			support-desk) app_port='$(SUPPORT_DESK_PORT)'; auth_port='$(SUPPORT_AUTH_PORT)'; mail_port='$(SUPPORT_MAILPIT_PORT)' ;; \
		esac; \
		wait_url() { ready=0; for _ in $$(seq 1 60); do curl -fsS "$$1" >/dev/null 2>&1 && { ready=1; break; }; sleep 1; done; test "$$ready" = 1 || { echo "readiness timeout: $$1"; return 1; }; }; \
		wait_url "http://127.0.0.1:$$auth_port/healthz" || exit $$?; \
		wait_url "http://127.0.0.1:$$mail_port/api/v1/messages?limit=1" || exit $$?; \
		wait_url "http://127.0.0.1:$$app_port/" || exit $$?; \
		$(COMPOSE) -p "auth-master-$$example" -f "$$example/docker-compose.yml" --profile seed run --rm seed || exit $$?; \
		if test "$$example" = minio-storage; then \
			$(COMPOSE) -p "auth-master-$$example" -f "$$example/docker-compose.yml" --profile integration run --rm --no-deps integration || exit $$?; \
		fi; \
		EXAMPLE_INTEGRATION="$$example" INTEGRATION_AUTH_URL="http://127.0.0.1:$$auth_port" INTEGRATION_MAILPIT_URL="http://127.0.0.1:$$mail_port" INTEGRATION_APP_URL="http://127.0.0.1:$$app_port" $(TESTSUM) ./integration -count=1 || exit $$?; \
		$(COMPOSE) -p "auth-master-$$example" -f "$$example/docker-compose.yml" down -v; trap - EXIT; \
	done

test-e2e:
	@for example in $(EXAMPLES); do \
		echo "==> $$example browser"; \
		trap '$(COMPOSE) -p "auth-master-'"$$example"'" -f "'"$$example"'/docker-compose.yml" down -v' EXIT; \
		$(COMPOSE) -p "auth-master-$$example" -f "$$example/docker-compose.yml" up -d --build || exit $$?; \
		case "$$example" in minio-storage) port='$(MINIO_STORAGE_PORT)' ;; deployment-api) port='$(DEPLOYMENT_API_PORT)' ;; support-desk) port='$(SUPPORT_DESK_PORT)' ;; esac; \
		ready=0; for _ in $$(seq 1 60); do curl -fsS "http://127.0.0.1:$$port/" >/dev/null 2>&1 && { ready=1; break; }; sleep 1; done; \
		test "$$ready" = 1 || { echo "readiness timeout: http://127.0.0.1:$$port/"; exit 1; }; \
		$(COMPOSE) -p "auth-master-$$example" -f "$$example/docker-compose.yml" --profile seed run --rm seed || exit $$?; \
		npx playwright test --project="$$example" || exit $$?; \
		$(COMPOSE) -p "auth-master-$$example" -f "$$example/docker-compose.yml" down -v; trap - EXIT; \
	done

test:
	@fails=""; \
	$(MAKE) --no-print-directory lint || fails="$$fails lint"; \
	$(MAKE) --no-print-directory test-unit || fails="$$fails unit"; \
	$(MAKE) --no-print-directory test-race || fails="$$fails race"; \
	$(MAKE) --no-print-directory test-integration || fails="$$fails integration"; \
	$(MAKE) --no-print-directory test-e2e || fails="$$fails e2e"; \
	test -z "$$fails" || { echo "failed groups:$$fails"; exit 1; }

down:
	@if test -n "$(EXAMPLE)"; then \
		case " $(EXAMPLES) " in *" $(EXAMPLE) "*) ;; *) echo "unsupported EXAMPLE=$(EXAMPLE)"; exit 2 ;; esac; \
		$(COMPOSE) -p "auth-master-$(EXAMPLE)" -f "$(EXAMPLE)/docker-compose.yml" down -v; \
	else \
		for example in $(EXAMPLES); do $(COMPOSE) -p "auth-master-$$example" -f "$$example/docker-compose.yml" down -v || true; done; \
	fi

reset:
	@test -n "$(EXAMPLE)" || { echo "EXAMPLE is required"; exit 2; }
	$(MAKE) --no-print-directory down EXAMPLE="$(EXAMPLE)"
	$(MAKE) --no-print-directory up EXAMPLE="$(EXAMPLE)"
