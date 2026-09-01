package mcpserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const tokenRefreshSkew = 30 * time.Second

// ClientConfig contains only MCP-to-authd connection settings. Credentials are
// process configuration, never MCP tool inputs, so a model cannot read or
// replace them through the protocol.
type ClientConfig struct {
	Address           string
	ServiceLogin      string
	ServiceSecret     string
	TLSCAFile         string
	TLSServerName     string
	RequestTimeout    time.Duration
	InsecureTransport bool
}

func ConfigFromEnv() (ClientConfig, error) {
	cfg := ClientConfig{
		Address:        valueOrDefault(os.Getenv("AUTH_MASTER_GRPC_ADDR"), "localhost:9090"),
		ServiceLogin:   strings.TrimSpace(os.Getenv("AUTH_MASTER_SERVICE_LOGIN")),
		ServiceSecret:  os.Getenv("AUTH_MASTER_SERVICE_SECRET"),
		TLSCAFile:      strings.TrimSpace(os.Getenv("AUTH_MASTER_GRPC_TLS_CA_FILE")),
		TLSServerName:  strings.TrimSpace(os.Getenv("AUTH_MASTER_GRPC_TLS_SERVER_NAME")),
		RequestTimeout: 10 * time.Second,
	}
	if raw := strings.TrimSpace(os.Getenv("AUTH_MASTER_REQUEST_TIMEOUT")); raw != "" {
		timeout, err := time.ParseDuration(raw)
		if err != nil || timeout <= 0 {
			return ClientConfig{}, fmt.Errorf("AUTH_MASTER_REQUEST_TIMEOUT must be a positive duration")
		}
		cfg.RequestTimeout = timeout
	}
	if cfg.ServiceLogin == "" {
		return ClientConfig{}, errors.New("AUTH_MASTER_SERVICE_LOGIN is required")
	}
	if cfg.ServiceSecret == "" {
		return ClientConfig{}, errors.New("AUTH_MASTER_SERVICE_SECRET is required")
	}
	if cfg.TLSCAFile == "" {
		cfg.InsecureTransport = true
	}
	return cfg, nil
}

func valueOrDefault(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

func Dial(ctx context.Context, cfg ClientConfig) (*Client, error) {
	creds, err := transportCredentials(cfg)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(cfg.Address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("create auth-master gRPC client: %w", err)
	}
	return NewClient(conn, cfg.ServiceLogin, cfg.ServiceSecret, cfg.RequestTimeout), nil
}

func transportCredentials(cfg ClientConfig) (credentials.TransportCredentials, error) {
	if cfg.InsecureTransport {
		return insecure.NewCredentials(), nil
	}
	caPEM, err := os.ReadFile(cfg.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("read auth-master TLS CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("AUTH_MASTER_GRPC_TLS_CA_FILE contains no valid certificates")
	}
	return credentials.NewTLS(&tls.Config{ // #nosec G402 -- minimum TLS is set explicitly.
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: cfg.TLSServerName,
	}), nil
}

type Client struct {
	conn    *grpc.ClientConn
	auth    authv1.AuthServiceClient
	admin   authv1.AdminServiceClient
	roles   authv1.RoleServiceClient
	login   string
	secret  string
	timeout time.Duration

	tokenMu      sync.Mutex
	accessToken  string
	tokenExpires time.Time
}

func NewClient(conn *grpc.ClientConn, login, secret string, timeout time.Duration) *Client {
	return &Client{
		conn: conn, auth: authv1.NewAuthServiceClient(conn), admin: authv1.NewAdminServiceClient(conn),
		roles: authv1.NewRoleServiceClient(conn), login: login, secret: secret, timeout: timeout,
	}
}

func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) actorContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	token, err := c.token(ctx)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token), cancel, nil
}

func (c *Client) token(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.accessToken != "" && time.Until(c.tokenExpires) > tokenRefreshSkew {
		return c.accessToken, nil
	}
	response, err := c.auth.IssueServiceToken(ctx, &authv1.IssueServiceTokenRequest{Login: c.login, Secret: c.secret})
	if err != nil {
		return "", fmt.Errorf("issue auth-master service token: %w", err)
	}
	if response.GetAccessToken() == "" || response.GetExpiresAt() == nil {
		return "", errors.New("auth-master returned an incomplete service token")
	}
	if err := response.GetExpiresAt().CheckValid(); err != nil {
		return "", fmt.Errorf("auth-master returned an invalid token expiry: %w", err)
	}
	c.accessToken = response.GetAccessToken()
	c.tokenExpires = response.GetExpiresAt().AsTime()
	return c.accessToken, nil
}

func (c *Client) ListUsers(ctx context.Context, in ListInput) (*authv1.ListUsersResponse, error) {
	ctx, cancel, err := c.actorContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return c.admin.ListUsers(ctx, &authv1.ListUsersRequest{Page: pageRequest(in)})
}

func (c *Client) ListRoles(ctx context.Context, in ListInput) (*authv1.ListRolesResponse, error) {
	ctx, cancel, err := c.actorContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return c.roles.ListRoles(ctx, &authv1.ListRolesRequest{Page: pageRequest(in)})
}

func pageRequest(in ListInput) *authv1.PageRequest {
	return &authv1.PageRequest{Query: in.Query, Cursor: in.Cursor, PageSize: int32(in.PageSize)}
}

func (c *Client) CreateRole(ctx context.Context, in CreateRoleInput) (string, error) {
	ctx, cancel, err := c.actorContext(ctx)
	if err != nil {
		return "", err
	}
	defer cancel()
	response, err := c.roles.CreateRole(ctx, &authv1.CreateRoleRequest{Name: in.Name, Description: in.Description, ParentIds: in.ParentIDs})
	if err != nil {
		return "", err
	}
	return response.GetRoleId(), nil
}

func (c *Client) AssignRole(ctx context.Context, in AssignRoleInput) error {
	level, err := parseRoleLevel(in.Level)
	if err != nil {
		return err
	}
	ctx, cancel, err := c.actorContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	_, err = c.roles.AssignRole(ctx, &authv1.AssignRoleRequest{RoleId: in.RoleID, UserId: in.UserID, Level: level, TagGrants: in.Tags})
	return err
}

func parseRoleLevel(level string) (authv1.RoleLevel, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "direct_member":
		return authv1.RoleLevel_ROLE_LEVEL_DIRECT_MEMBER, nil
	case "member":
		return authv1.RoleLevel_ROLE_LEVEL_MEMBER, nil
	case "role_admin":
		return authv1.RoleLevel_ROLE_LEVEL_ROLE_ADMIN, nil
	default:
		return authv1.RoleLevel_ROLE_LEVEL_UNSPECIFIED, errors.New("level must be direct_member, member, or role_admin")
	}
}

func (c *Client) RemoveRole(ctx context.Context, in MembershipInput) error {
	ctx, cancel, err := c.actorContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	_, err = c.roles.RemoveRole(ctx, &authv1.RemoveRoleRequest{RoleId: in.RoleID, UserId: in.UserID})
	return err
}

func (c *Client) BanUser(ctx context.Context, in BanUserInput) error {
	ctx, cancel, err := c.actorContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	_, err = c.admin.BanUser(ctx, &authv1.BanUserRequest{UserId: in.UserID, Reason: in.Reason})
	return err
}

func (c *Client) UnbanUser(ctx context.Context, in UserInput) error {
	ctx, cancel, err := c.actorContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	_, err = c.admin.UnbanUser(ctx, &authv1.UnbanUserRequest{UserId: in.UserID})
	return err
}

func (c *Client) ChangeRoleTag(ctx context.Context, in RoleTagInput, add bool) error {
	ctx, cancel, err := c.actorContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if add {
		_, err = c.roles.AddRoleTag(ctx, &authv1.AddRoleTagRequest{RoleId: in.RoleID, Tag: in.Tag})
	} else {
		_, err = c.roles.DeleteRoleTag(ctx, &authv1.DeleteRoleTagRequest{RoleId: in.RoleID, Tag: in.Tag})
	}
	return err
}

func (c *Client) ChangeMembershipTag(ctx context.Context, in MembershipTagInput, add bool) error {
	ctx, cancel, err := c.actorContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if add {
		_, err = c.roles.GrantMembershipTag(ctx, &authv1.GrantMembershipTagRequest{RoleId: in.RoleID, UserId: in.UserID, Tag: in.Tag})
	} else {
		_, err = c.roles.RevokeMembershipTag(ctx, &authv1.RevokeMembershipTagRequest{RoleId: in.RoleID, UserId: in.UserID, Tag: in.Tag})
	}
	return err
}

func (c *Client) ListUserRoles(ctx context.Context, in UserInput) (*authv1.ListUserRolesResponse, error) {
	ctx, cancel, err := c.actorContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return c.roles.ListUserRoles(ctx, &authv1.ListUserRolesRequest{UserId: in.UserID})
}

func (c *Client) ListRoleMembers(ctx context.Context, in RoleInput) (*authv1.ListRoleMembersResponse, error) {
	ctx, cancel, err := c.actorContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return c.roles.ListRoleMembers(ctx, &authv1.ListRoleMembersRequest{RoleId: in.RoleID})
}
