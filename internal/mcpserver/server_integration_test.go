package mcpserver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/olegkapshai/auth-master/internal/config"
	"github.com/olegkapshai/auth-master/internal/crypto"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/olegkapshai/auth-master/internal/migrate"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/olegkapshai/auth-master/internal/service"
	"github.com/olegkapshai/auth-master/internal/testutil"
	grpctransport "github.com/olegkapshai/auth-master/internal/transport/grpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestIntegrationMCPServiceCredentialRBACJourney(t *testing.T) {
	ctx := context.Background()
	dsn, terminate := testutil.StartPostgres16TestcontainerForTest(t, ctx)
	defer terminate()
	db, err := migrate.Open(dsn)
	require.NoError(t, err)
	require.NoError(t, migrate.Up(db))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	defer sqlDB.Close()

	repo := repository.New(db)
	key := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	cfg := &config.Config{
		PasswordHistoryEncryptionKey: key, SigningKeyMasterKey: key,
		AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, SigningGracePeriod: time.Minute,
		PasswordMaxAge: 365 * 24 * time.Hour, PasswordHistoryN: 5, OTPCodeTTL: time.Minute,
		OTPCodeLength: 6, OTPMaxAttempts: 5, MaxSessionsPerUser: 10, LoginFailWindow: time.Minute,
		LoginFailMax: 10, LoginLockDuration: time.Minute, NotifyOnFailThreshold: 99,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auth, err := service.NewAuth(cfg, repo, &mail.Sender{Host: "127.0.0.1", Port: 1, From: "mcp@test.dev"}, logger)
	require.NoError(t, err)
	require.NoError(t, auth.EnsureBootstrap(ctx))

	secret := "MCP-Service1!"
	secretHash, err := crypto.HashSecret(secret)
	require.NoError(t, err)
	_, err = repo.CreateServiceUser(ctx, "mcp-integration", secretHash, true)
	require.NoError(t, err)
	passwordHash, err := crypto.HashPassword("Human-Pass1!")
	require.NoError(t, err)
	humanID, err := repo.CreateHumanUser(ctx, "mcp-human", "mcp-human@test.dev", passwordHash)
	require.NoError(t, err)

	grpcServer, _ := grpctransport.New(auth, repo, logger, grpctransport.Options{})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveDone := make(chan error, 1)
	go func() { serveDone <- grpcServer.Serve(listener) }()
	t.Cleanup(func() { grpcServer.Stop(); <-serveDone })

	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	backend := NewClient(conn, "mcp-integration", secret, 3*time.Second)
	t.Cleanup(func() { require.NoError(t, backend.Close()) })
	session := connectTestClient(t, backend)

	created, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "create_role", Arguments: map[string]any{"name": "mcp-operators"}})
	require.NoError(t, err)
	require.False(t, created.IsError)
	createdMap := created.StructuredContent.(map[string]any)
	roleID := createdMap["role_id"].(string)
	require.NotEmpty(t, roleID)

	assigned, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "assign_role", Arguments: map[string]any{
		"role_id": roleID, "user_id": humanID.String(), "level": "role_admin",
	}})
	require.NoError(t, err)
	require.False(t, assigned.IsError)

	members, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_role_members", Arguments: map[string]any{"role_id": roleID}})
	require.NoError(t, err)
	require.False(t, members.IsError)
	membersMap := members.StructuredContent.(map[string]any)
	require.Len(t, membersMap["members"], 1)

	roles, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_roles", Arguments: map[string]any{"query": "operators"}})
	require.NoError(t, err)
	require.False(t, roles.IsError)
	rolesMap := roles.StructuredContent.(map[string]any)
	require.Len(t, rolesMap["items"], 1)
}
