# Архитектура бэкенда на Go
Выбор баз данных

## PostgreSQL (основная БД):
- хранение пользователей (users);
- хранение токенов (refresh_tokens);
- хранение ролей и прав (roles, permissions);
- связи пользователей с ролями (user_roles).

## Redis (кэш):
- хранение активных JWT‑токенов (для быстрой проверки);
- временное хранение OTP‑кодов (срок жизни 5–10 мин);
- лимитирование запросов (rate limiting).

## Основные пакеты/библиотеки Go
- golang.org/x/crypto/bcrypt — хеширование паролей;
- github.com/dgrijalva/jwt-go или golang-jwt/jwt — работа с JWT;
- github.com/grpc-ecosystem/go-grpc-middleware — middleware для gRPC;
- github.com/go-redis/redis/v8 — клиент Redis;
- gorm.io/gorm — ORM для PostgreSQL.

## HTTP‑эндпоинты (REST API)
1. POST /api/v1/auth/register\
Регистрация пользователя по email.\
Тело: { "email": "user@example.com", "password": "secret" }.\
Ответ: 201 Created или ошибки валидации.

2. POST /api/v1/auth/login\
Вход по email + пароль.\
Тело: { "email": "user@example.com", "password": "secret" }.\
Ответ: JWT‑токены (access, refresh).

3. POST /api/v1/auth/login/otp\
Вход по OTP‑коду (после запроса кода).\
Тело: { "email": "user@example.com", "otp": "123456" }.

4. POST /api/v1/auth/otp/request\
Запрос OTP‑кода на email.\
Тело: { "email": "user@example.com" }.

5. POST /api/v1/auth/2fa/enable\
Включение 2FA (после подтверждения кода).\
Требуется текущий пароль.

6. POST /api/v1/auth/2fa/verify\
Проверка кода 2FA (например, для смены почты).\
Тело: { "otp": "123456" }.\

7. PUT /api/v1/auth/change-password\
Смена пароля (требуется текущий пароль).\
Тело: { "current_password": "...", "new_password": "..." }.

8. PUT /api/v1/auth/change-email\
Смена email (с 2FA).\
Тело: { "new_email": "new@example.com", "otp": "123456" }.

9. POST /api/v1/auth/refresh\
Обновление access-токена по refresh-токену.\
Тело: { "refresh_token": "..." }.

10. POST /api/v1/auth/logout\
Аннулирование refresh-токена.\
Требуется refresh_token в теле или заголовке.

## gRPC‑эндпоинты
1. AuthService.ValidateAccessToken\
Проверка JWT access-токена (для внутренних сервисов).\
Входной параметр: token: string.\
Выход: is_valid: bool, claims: map<string, string>, error: string.

2. AuthService.IssueServiceToken\
Выдача токена для бэкенд‑сервиса (по сертификату/секрету).\
Входной параметр: service_id: string, credentials: bytes.\
Выход: token: string, error: string.

3. RoleService.CheckRole\
Проверка, имеет ли субъект (пользователь/сервис) роль.\
Входной параметр: subject_id: string, role: string, context: map<string, string>.\
Выход: has_role: bool, error: string.

4. RoleService.AddUserToRole\
Добавление пользователя в роль (доступно создателям ролей/сервисов).\
Входной параметр: user_id: string, role: string, issuer_id: string.\
Выход: success: bool, error: string.

5. RoleService.ListRoles\
Получение списка ролей для субъекта.\
Входной параметр: subject_id: string.\
Выход: roles: repeated string, error: string.

6. TokenService.InvalidateRefreshToken\
Аннулирование refresh-токена (например, при логауте).\
Входной параметр: token_id: string, subject_id: string.\
Выход: success: bool, error: string.

## Модель данных (PostgreSQL)
1. users
    - id (UUID);
    - email (unique);
    - password_hash (bcrypt);
    - 2fa_enabled (boolean);
    - 2fa_secret (base32);
    - created_at, updated_at.

2. refresh_tokens
    - token_id (UUID);
    - user_id (FK to users.id);
    - device_id (string);
    - browser (string);
    - ip_address (inet);
    - expires_at (timestamptz);
    - used (boolean, default false);
    - created_at.

3. roles
    - role_id (UUID);
    - name (string, unique);
    - description (text);
    - is_system (boolean, для суперпользователей);
    - created_by (FK to users.id).

4. user_roles
    - user_id (FK);
    - role_id (FK);
    - assigned_by (FK to users.id);
    - assigned_at.

5. services
    - service_id (UUID);
    - name (string);
    - api_key_hash (bcrypt);
    - allowed_roles (array of role_ids).

## Ключевые механизмы
### JWT‑токены
access: короткий срок (15–30 мин), содержит user_id, roles, device_id.\
refresh: долгий срок (7–30 дней), одноразовый, хранится в БД с метаданными устройства.

### 2FA
Использование TOTP (RFC 6238) с секретом в users.2fa_secret.\
Код проверяется при смене email, критичных операциях.

### OTP
Генерируется как 6‑значный код, хранится в Redis с TTL.\
Ограничение: не более 3 запросов за 5 мин.

### Ролевая модель
Суперпользователи (is_system=true) имеют все роли.\
Сервисы могут назначать роли пользователям в рамках своих прав.\
Проверка ролей учитывает контекст (например, проект/ресурс).

### Безопасность
Все пароли хешируются bcrypt (cost=12).\
Токены передаются только через HTTPS.\
Rate limiting на все эндпоинты (Redis).\
Логирование критических действий (смена email, пароля, ролей).

## Запуск
```bash
protoc --go_out=. --go_grpc_out=. proto/auth.proto\
go build -o auth-service cmd/main.go\

gorm auto-migrate
source .env && ./auth-service
```
