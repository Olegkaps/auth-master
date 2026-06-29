# auth-master

Сервис аутентификации и авторизации на Go: REST (chi), PostgreSQL, JWT (access + refresh с ротацией signing keys), роли и запросы ролей, email OTP (в т.ч. step-up 2FA по REST), политика паролей, Swagger UI, метрики Prometheus.

## Требования

- Go 1.25+
- **Podman** или **Docker** + **Compose** — для Postgres/Mailpit, сборки образа и интеграционных тестов в `docker-compose.test.yml`
- Node 20+ (для фронтенда в `web/`)

## Разработка бэкенда и CI

- Локально: `make check` (форматирование, `golangci-lint`, `go test ./...`). Установка линтера: `make lint-go-install`.
- **После любых изменений в бэкенде** (`cmd/`, `internal/`, `tools/`, `go.mod`) обязательно прогоните интеграцию и coverage gate **в контейнере** (как в GitHub Actions):
  - `make docker-test-integration` или `docker compose -f docker-compose.test.yml run --rm test-integration`
  - с Podman: `make podman-test-integration` или `podman compose -f docker-compose.test.yml run --rm test-integration`
- Правила для агента Cursor: `.cursor/rules/backend-quality.mdc`.

## Быстрый старт

1. Скопируйте переменные окружения:

   ```bash
   cp .env.example .env
   ```

2. Поднимите Postgres, Mailpit и бэкенд `authd` (все сервисы читают `.env` через `env_file`; у `authd` в compose переопределены `DATABASE_URL` и `SMTP_HOST` на хосты `postgres` и `mailpit`):

   ```bash
   podman compose up -d
   ```

   HTTP: `http://localhost:${HTTP_PORT:-8080}`.

3. Либо поднимите только инфраструктуру и запускайте API с хоста:

   ```bash
   podman compose up -d postgres mailpit
   go run ./cmd/authd
   ```

По умолчанию HTTP слушает адрес из `HTTP_ADDR`. Миграции схемы выполняются при старте через **GORM AutoMigrate** и вспомогательный SQL (enum-типы, частичные уникальные индексы, ограничения `CHECK`).

## Образ бэкенда (production)

Сборка: в Dockerfile используются cache mounts (`RUN --mount=type=cache,...`); **Podman** и **Docker с BuildKit** их подхватывают при пересборке.

```bash
podman build -t authd:local .
```

(Эквивалент с Docker: `DOCKER_BUILDKIT=1 docker build -t authd:local .`)

Итоговый слой — **`scratch`** + статический бинарник (`CGO_ENABLED=0`, `-ldflags="-s -w"`, `-trimpath`) и системный пакет CA для TLS к Postgres/SMTP. Запуск:

```bash
podman run --rm -p 8080:8080 --env-file .env authd:local
```

Переменные из `.env` должны задавать `DATABASE_URL`, секреты и адреса прослушивания так же, как при локальном `go run`.

Кросс-сборка (пример):

```bash
podman build --arch arm64 --os linux -t authd:arm64 .
```

## Compose: тесты в контейнере (Docker / Podman)

Файл `docker-compose.test.yml` рассчитан на **`podman compose`**: тома для кэша модулей и сборки Go.

- **`test-integration`** — Postgres в том же compose, `INTEGRATION_DATABASE_URL`, сокет OCI не нужен.
- **`test`** — интеграционные тесты через Testcontainers: в контейнер монтируется сокет Podman (`PODMAN_SOCKET` → `/var/run/docker.sock`). Цель `make podman-test` сама берёт путь из `podman info`, иначе задайте вручную:

```bash
export PODMAN_SOCKET="${XDG_RUNTIME_DIR}/podman/podman.sock"
# или: export PODMAN_SOCKET="$(podman info -f '{{.Host.RemoteSocket.Path}}')"
```

```bash
podman compose -f docker-compose.test.yml run --rm test
podman compose -f docker-compose.test.yml run --rm test-integration
podman compose -f docker-compose.test.yml run --rm test-coverage
```

Через Makefile:

```bash
make podman-test
make podman-test-integration
```

Локально без Compose интеграционные тесты ожидают работающий **`podman info`** или **`docker info`** (см. `internal/testutil`). При rootless Podman часто помогает:

```bash
export DOCKER_HOST="unix://${XDG_RUNTIME_DIR}/podman/podman.sock"
```

`-race` в compose не включён (нужен CGO); гонку удобнее запускать на хосте: `go test ./... -race`.

## Переменные окружения

См. `.env.example`: строка подключения к БД (`DATABASE_URL`), ключи шифрования истории паролей и мастер-ключ подписи JWT, SMTP, TTL токенов, лимиты сессий и политика паролей.

## Фронтенд

```bash
cd web && npm ci && npm run dev
```

Сборка статики:

```bash
make web-build
```

## Тесты и покрытие

```bash
make test
```

Интеграционные тесты используют Testcontainers (нужен **Podman** или Docker с доступным API). Чтобы пропустить их:

```bash
SKIP_TESTCONTAINERS=1 go test ./... -count=1
```

Проверка, что суммарное покрытие пакетов `./internal/...` не ниже **70%** (с учётом интеграционных тестов):

```bash
make test-integration
```

Цель `test-integration` запускает `go test -tags=covgate ./internal/covgate`. Сначала выполняется пробный запуск Postgres через Testcontainers: если контейнер не поднимается (в т.ч. при ошибке провайдера вроде «rootless Docker not found»), порог **пропускается** (`Skip`), чтобы `make test-integration` не ломал локальную среду без рабочего OCI. В CI, где Docker обязателен, задайте **`REQUIRE_COVERAGE_GATE=1`**: тогда отсутствие контейнера даст **ошибку**, а не пропуск.

Для ручной оценки покрытия без порога:

```bash
go test $(go list ./internal/...) -count=1 -coverprofile=c.out \
  -coverpkg=$(go list ./internal/... | paste -sd, -)
go tool cover -func=c.out
```

## OpenAPI / Swagger

Спецификация **генерируется** утилитой [swag](https://github.com/swaggo/swag) из комментариев над обработчиками в `internal/transport/http` и общих настроек в `cmd/authd/main.go`. В репозиторий коммитятся сгенерированные `docs/docs.go`, `docs/swagger.json`, `docs/swagger.yaml`.

Пересборка:

```bash
make swagger
```

(эквивалент: `go run github.com/swaggo/swag/cmd/swag@v1.16.4 init -g cmd/authd/main.go -o docs --parseInternal`)

UI: после `go run ./cmd/authd` откройте `http://localhost:8080/swagger/index.html` (или ваш `HTTP_ADDR`). В спецификации `basePath` равен `/`, пути API указаны полностью, например `/v1/auth/login`.

## Структура

- `cmd/authd` — точка входа
- `internal/config` — конфигурация (cleanenv)
- `internal/repository` — доступ к БД (**GORM**)
- `internal/migrate` — открытие БД и вызов миграций
- `internal/testutil` — общие проверки для тестов (наличие Podman/Docker)
- `internal/service` — доменная логика
- `internal/transport/http` — REST API
- `web/` — Vite + TypeScript клиент

## Моки в тестах

Для изоляции слоя сервиса удобно ввести интерфейс над методами `repository.Store` и использовать, например, `github.com/stretchr/testify/mock` или ручные фейки; в репозитории сейчас основной упор на интеграционные тесты с реальной Postgres через Testcontainers.
