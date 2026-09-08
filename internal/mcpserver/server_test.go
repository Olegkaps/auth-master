package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeBackend struct {
	listUsersInput ListInput
	assignInput    AssignRoleInput
	err            error
}

func (f *fakeBackend) ListUsers(_ context.Context, in ListInput) (*authv1.ListUsersResponse, error) {
	f.listUsersInput = in
	if f.err != nil {
		return nil, f.err
	}
	total := int64(1)
	email := "ada@example.test"
	return &authv1.ListUsersResponse{
		Users:    []*authv1.User{{Id: "user-1", Login: "ada", Email: &email, Kind: authv1.UserKind_USER_KIND_HUMAN, CreatedAt: timestamppb.New(time.Unix(10, 0))}},
		PageSize: 25, Total: &total, NextCursor: "next-users",
	}, nil
}

func (f *fakeBackend) ListRoles(context.Context, ListInput) (*authv1.ListRolesResponse, error) {
	return &authv1.ListRolesResponse{}, f.err
}

func (f *fakeBackend) CreateRole(context.Context, CreateRoleInput) (string, error) {
	return "role-1", f.err
}

func (f *fakeBackend) AssignRole(_ context.Context, in AssignRoleInput) error {
	f.assignInput = in
	return f.err
}

func (f *fakeBackend) RemoveRole(context.Context, MembershipInput) error { return f.err }
func (f *fakeBackend) BanUser(context.Context, BanUserInput) error       { return f.err }
func (f *fakeBackend) UnbanUser(context.Context, UserInput) error        { return f.err }
func (f *fakeBackend) ChangeRoleTag(context.Context, RoleTagInput, bool) error {
	return f.err
}
func (f *fakeBackend) ChangeMembershipTag(context.Context, MembershipTagInput, bool) error {
	return f.err
}
func (f *fakeBackend) ListUserRoles(context.Context, UserInput) (*authv1.ListUserRolesResponse, error) {
	return &authv1.ListUserRolesResponse{}, f.err
}
func (f *fakeBackend) ListRoleMembers(context.Context, RoleInput) (*authv1.ListRoleMembersResponse, error) {
	return &authv1.ListRoleMembersResponse{}, f.err
}

func connectTestClient(t *testing.T, backend Backend) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := New(backend).Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	client := mcp.NewClient(&mcp.Implementation{Name: "auth-master-test", Version: "1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, clientSession.Close())
		_ = serverSession.Close()
	})
	return clientSession
}

func TestServerPublishesBoundedCredentialFreeToolSurface(t *testing.T) {
	session := connectTestClient(t, &fakeBackend{})
	result, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, result.Tools, 13)

	encoded, err := json.Marshal(result.Tools)
	require.NoError(t, err)
	schemas := strings.ToLower(string(encoded))
	require.NotContains(t, schemas, "secret")
	require.NotContains(t, schemas, "access_token")
	require.NotContains(t, schemas, "service_login")

	tools := make(map[string]*mcp.Tool, len(result.Tools))
	for _, tool := range result.Tools {
		tools[tool.Name] = tool
	}
	require.True(t, tools["list_users"].Annotations.ReadOnlyHint)
	require.Equal(t, false, *tools["create_role"].Annotations.DestructiveHint)
	require.Equal(t, true, *tools["ban_user"].Annotations.DestructiveHint)
}

func TestListUsersReturnsStructuredPageAndAppliesDefaultPageSize(t *testing.T) {
	backend := &fakeBackend{}
	session := connectTestClient(t, backend)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_users", Arguments: map[string]any{"query": "Ada"}})
	require.NoError(t, err)
	require.False(t, result.IsError)
	require.Equal(t, 25, backend.listUsersInput.PageSize)

	encoded, err := json.Marshal(result.StructuredContent)
	require.NoError(t, err)
	var output struct {
		Items []UserOutput `json:"items"`
		Total int64        `json:"total"`
	}
	require.NoError(t, json.Unmarshal(encoded, &output))
	require.Equal(t, int64(1), output.Total)
	require.Equal(t, "ada", output.Items[0].Login)
	require.Equal(t, "ada@example.test", *output.Items[0].Email)
}

func TestMutationFailureIsAnMCPToolErrorWithoutLeakingCredentials(t *testing.T) {
	backend := &fakeBackend{err: errors.New("permission denied")}
	session := connectTestClient(t, backend)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "assign_role", Arguments: map[string]any{"role_id": "role-1", "user_id": "user-1", "level": "member"},
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Len(t, result.Content, 1)
	text := result.Content[0].(*mcp.TextContent).Text
	require.Contains(t, text, "assign role")
	require.NotContains(t, text, "AUTH_MASTER_SERVICE_SECRET")
}

func TestParseRoleLevelDefaultsClosed(t *testing.T) {
	for input, expected := range map[string]authv1.RoleLevel{
		"direct_member": authv1.RoleLevel_ROLE_LEVEL_DIRECT_MEMBER,
		" member ":      authv1.RoleLevel_ROLE_LEVEL_MEMBER,
		"ROLE_ADMIN":    authv1.RoleLevel_ROLE_LEVEL_ROLE_ADMIN,
	} {
		actual, err := parseRoleLevel(input)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
	_, err := parseRoleLevel("owner")
	require.Error(t, err)
}

func TestConfigFromEnvRequiresCredentialPairAndValidTimeout(t *testing.T) {
	t.Setenv("AUTH_MASTER_SERVICE_LOGIN", "")
	t.Setenv("AUTH_MASTER_SERVICE_SECRET", "")
	_, err := ConfigFromEnv()
	require.EqualError(t, err, "AUTH_MASTER_SERVICE_LOGIN is required")

	t.Setenv("AUTH_MASTER_SERVICE_LOGIN", "mcp")
	t.Setenv("AUTH_MASTER_SERVICE_SECRET", "Service-Secret1!")
	t.Setenv("AUTH_MASTER_REQUEST_TIMEOUT", "0s")
	_, err = ConfigFromEnv()
	require.EqualError(t, err, "AUTH_MASTER_REQUEST_TIMEOUT must be a positive duration")

	t.Setenv("AUTH_MASTER_REQUEST_TIMEOUT", "3s")
	cfg, err := ConfigFromEnv()
	require.NoError(t, err)
	require.Equal(t, "localhost:9090", cfg.Address)
	require.Equal(t, 3*time.Second, cfg.RequestTimeout)
	require.True(t, cfg.InsecureTransport)
}
