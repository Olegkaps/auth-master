package testutil

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	pgmod "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TryStartPostgres16Testcontainer attempts to start Postgres via Testcontainers.
// When INTEGRATION_DATABASE_URL is set (e.g. podman compose + postgres in docker-compose.test.yml),
// a fresh ephemeral database is created on that server and dropped in terminate(). That avoids sharing
// one DB across parallel `go test` packages and dirty state between tests.
// It returns ok=false (without panicking) when SKIP_TESTCONTAINERS is set, OCI is unavailable,
// or Testcontainers fails including provider panics ("rootless Docker not found", etc.).
func TryStartPostgres16Testcontainer(ctx context.Context) (dsn string, terminate func(), ok bool) {
	if base := strings.TrimSpace(os.Getenv("INTEGRATION_DATABASE_URL")); base != "" {
		child, cleanup, err := provisionEphemeralPostgresDB(ctx, base)
		if err != nil {
			return "", nil, false
		}
		return child, cleanup, true
	}
	if os.Getenv("SKIP_TESTCONTAINERS") != "" {
		return "", nil, false
	}
	if !OCIProviderAvailable() {
		return "", nil, false
	}

	var c *pgmod.PostgresContainer
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("%v", r)
			}
		}()
		c, err = pgmod.Run(ctx,
			"postgres:16-alpine",
			pgmod.WithDatabase("auth"),
			pgmod.WithUsername("auth"),
			pgmod.WithPassword("auth"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp")),
		)
	}()

	if err != nil || c == nil {
		return "", nil, false
	}

	dsn, err = c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = c.Terminate(ctx)
		return "", nil, false
	}
	return dsn, func() { _ = c.Terminate(ctx) }, true
}

func postgresAdminDSN(baseDSN string) (string, error) {
	u, err := url.Parse(baseDSN)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "postgres", "postgresql":
	default:
		return "", fmt.Errorf("unsupported URL scheme %q (expected postgres)", u.Scheme)
	}
	u.Path = "/postgres"
	return u.String(), nil
}

func postgresURLWithDatabase(baseDSN, dbName string) (string, error) {
	u, err := url.Parse(baseDSN)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "postgres", "postgresql":
	default:
		return "", fmt.Errorf("unsupported URL scheme %q (expected postgres)", u.Scheme)
	}
	u.Path = "/" + dbName
	return u.String(), nil
}

func randomDBName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "auth_test_" + hex.EncodeToString(b[:]), nil
}

// provisionEphemeralPostgresDB connects to the server from baseDSN, CREATE DATABASE, returns a DSN to the new DB.
// terminate drops the database (WITH FORCE on Postgres 13+). dbName is alphanumeric-only.
func provisionEphemeralPostgresDB(ctx context.Context, baseDSN string) (dsn string, terminate func(), err error) {
	adminDSN, err := postgresAdminDSN(baseDSN)
	if err != nil {
		return "", nil, err
	}
	dbName, err := randomDBName()
	if err != nil {
		return "", nil, err
	}

	admin, err := sql.Open("pgx", adminDSN)
	if err != nil {
		return "", nil, err
	}
	admin.SetMaxOpenConns(1)
	defer admin.Close()

	pingCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := admin.PingContext(pingCtx); err != nil {
		return "", nil, fmt.Errorf("ping admin db: %w", err)
	}

	execCtx, cancel2 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel2()
	if _, err := admin.ExecContext(execCtx, "CREATE DATABASE "+dbName); err != nil {
		return "", nil, fmt.Errorf("create database %s: %w", dbName, err)
	}

	childDSN, err := postgresURLWithDatabase(baseDSN, dbName)
	if err != nil {
		dropCtx, cancel3 := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel3()
		_, _ = admin.ExecContext(dropCtx, "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
		return "", nil, err
	}

	cleanup := func() {
		dropCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		a, err := sql.Open("pgx", adminDSN)
		if err != nil {
			return
		}
		defer a.Close()
		_, _ = a.ExecContext(dropCtx, "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
	}

	return childDSN, cleanup, nil
}

// StartPostgres16TestcontainerForTest returns a DSN and a terminate callback, or skips the test
// when Testcontainers cannot use the local OCI runtime.
func StartPostgres16TestcontainerForTest(t *testing.T, ctx context.Context) (dsn string, terminate func()) {
	t.Helper()
	dsn, terminate, ok := TryStartPostgres16Testcontainer(ctx)
	if !ok {
		t.Skip("postgres testcontainer unavailable (set SKIP_TESTCONTAINERS=1 to skip explicitly)")
	}
	return dsn, terminate
}
