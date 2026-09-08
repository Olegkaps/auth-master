package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
)

const serverVersion = "1.0.0"

type Backend interface {
	ListUsers(context.Context, ListInput) (*authv1.ListUsersResponse, error)
	ListRoles(context.Context, ListInput) (*authv1.ListRolesResponse, error)
	CreateRole(context.Context, CreateRoleInput) (string, error)
	AssignRole(context.Context, AssignRoleInput) error
	RemoveRole(context.Context, MembershipInput) error
	BanUser(context.Context, BanUserInput) error
	UnbanUser(context.Context, UserInput) error
	ChangeRoleTag(context.Context, RoleTagInput, bool) error
	ChangeMembershipTag(context.Context, MembershipTagInput, bool) error
	ListUserRoles(context.Context, UserInput) (*authv1.ListUserRolesResponse, error)
	ListRoleMembers(context.Context, RoleInput) (*authv1.ListRoleMembersResponse, error)
}

type ListInput struct {
	Query    string `json:"query,omitempty" jsonschema:"case-insensitive name or login search"`
	Cursor   string `json:"cursor,omitempty" jsonschema:"opaque next_cursor from the previous response"`
	PageSize int    `json:"page_size,omitempty" jsonschema:"number of records to return, from 1 through 100"`
}

type UserInput struct {
	UserID string `json:"user_id" jsonschema:"auth-master user UUID"`
}

type RoleInput struct {
	RoleID string `json:"role_id" jsonschema:"auth-master role UUID"`
}

type CreateRoleInput struct {
	Name        string   `json:"name" jsonschema:"unique role name"`
	Description string   `json:"description,omitempty" jsonschema:"human-readable role description"`
	ParentIDs   []string `json:"parent_ids,omitempty" jsonschema:"zero or more parent role UUIDs"`
}

type AssignRoleInput struct {
	RoleID string   `json:"role_id" jsonschema:"role UUID to grant"`
	UserID string   `json:"user_id" jsonschema:"user UUID receiving the role"`
	Level  string   `json:"level" jsonschema:"membership level: direct_member, member, or role_admin"`
	Tags   []string `json:"tags,omitempty" jsonschema:"configured role tags to grant atomically with membership"`
}

type MembershipInput struct {
	RoleID string `json:"role_id" jsonschema:"role UUID"`
	UserID string `json:"user_id" jsonschema:"user UUID"`
}

type BanUserInput struct {
	UserID string `json:"user_id" jsonschema:"user UUID to ban"`
	Reason string `json:"reason" jsonschema:"auditable reason for the ban"`
}

type RoleTagInput struct {
	RoleID string `json:"role_id" jsonschema:"role UUID"`
	Tag    string `json:"tag" jsonschema:"normalized role tag"`
}

type MembershipTagInput struct {
	RoleID string `json:"role_id" jsonschema:"role UUID"`
	UserID string `json:"user_id" jsonschema:"user UUID"`
	Tag    string `json:"tag" jsonschema:"configured role tag"`
}

type PageOutput struct {
	Items      any    `json:"items"`
	PageSize   int32  `json:"page_size"`
	Total      *int64 `json:"total,omitempty"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type MutationOutput struct {
	Changed bool `json:"changed"`
}

type CreateRoleOutput struct {
	RoleID string `json:"role_id"`
}

type UserOutput struct {
	ID        string  `json:"id"`
	Login     string  `json:"login"`
	Email     *string `json:"email,omitempty"`
	Kind      string  `json:"kind"`
	Superuser bool    `json:"superuser"`
	BannedAt  *string `json:"banned_at,omitempty"`
	BanReason string  `json:"ban_reason,omitempty"`
	CreatedAt string  `json:"created_at"`
}

type RoleOutput struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	ParentIDs   []string `json:"parent_ids"`
	Tags        []string `json:"tags"`
	CreatedAt   string   `json:"created_at"`
}

type UserRoleOutput struct {
	ID         string  `json:"id"`
	UserID     string  `json:"user_id"`
	RoleID     string  `json:"role_id"`
	Level      string  `json:"level"`
	ValidFrom  string  `json:"valid_from"`
	ValidUntil *string `json:"valid_until,omitempty"`
	GrantedBy  *string `json:"granted_by,omitempty"`
}

type RoleMemberOutput struct {
	UserID string   `json:"user_id"`
	Login  string   `json:"login"`
	Email  *string  `json:"email,omitempty"`
	Level  string   `json:"level"`
	Tags   []string `json:"tags"`
}

type UserRolesOutput struct {
	UserRoles []UserRoleOutput `json:"user_roles"`
}

type RoleMembersOutput struct {
	Members []RoleMemberOutput `json:"members"`
}

func New(backend Backend) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name: "auth-master", Title: "auth-master administration", Version: serverVersion,
	}, &mcp.ServerOptions{Instructions: "Manage auth-master users and RBAC. Resolve user and role UUIDs with list tools before mutations. Never guess identifiers."})
	registerReadTools(server, backend)
	registerMutationTools(server, backend)
	return server
}

func registerReadTools(server *mcp.Server, backend Backend) {
	mcp.AddTool(server, readTool("list_users", "List users", "Search auth-master users with keyset pagination. Requires a superuser service account."), func(ctx context.Context, _ *mcp.CallToolRequest, in ListInput) (*mcp.CallToolResult, PageOutput, error) {
		response, err := backend.ListUsers(ctx, normalizeList(in))
		if err != nil {
			return nil, PageOutput{}, fmt.Errorf("list users: %w", err)
		}
		users := make([]UserOutput, 0, len(response.GetUsers()))
		for _, user := range response.GetUsers() {
			users = append(users, userOutput(user))
		}
		return nil, PageOutput{Items: users, PageSize: response.GetPageSize(), Total: response.Total, NextCursor: response.GetNextCursor()}, nil
	})
	mcp.AddTool(server, readTool("list_roles", "List roles", "Search auth-master roles with keyset pagination."), func(ctx context.Context, _ *mcp.CallToolRequest, in ListInput) (*mcp.CallToolResult, PageOutput, error) {
		response, err := backend.ListRoles(ctx, normalizeList(in))
		if err != nil {
			return nil, PageOutput{}, fmt.Errorf("list roles: %w", err)
		}
		roles := make([]RoleOutput, 0, len(response.GetRoles()))
		for _, role := range response.GetRoles() {
			roles = append(roles, roleOutput(role))
		}
		return nil, PageOutput{Items: roles, PageSize: response.GetPageSize(), Total: response.Total, NextCursor: response.GetNextCursor()}, nil
	})
	mcp.AddTool(server, readTool("list_user_roles", "List user roles", "List the direct active role memberships for one user."), func(ctx context.Context, _ *mcp.CallToolRequest, in UserInput) (*mcp.CallToolResult, UserRolesOutput, error) {
		response, err := backend.ListUserRoles(ctx, in)
		if err != nil {
			return nil, UserRolesOutput{}, fmt.Errorf("list user roles: %w", err)
		}
		out := UserRolesOutput{UserRoles: make([]UserRoleOutput, 0, len(response.GetUserRoles()))}
		for _, role := range response.GetUserRoles() {
			out.UserRoles = append(out.UserRoles, userRoleOutput(role))
		}
		return nil, out, nil
	})
	mcp.AddTool(server, readTool("list_role_members", "List role members", "List direct active members of one role."), func(ctx context.Context, _ *mcp.CallToolRequest, in RoleInput) (*mcp.CallToolResult, RoleMembersOutput, error) {
		response, err := backend.ListRoleMembers(ctx, in)
		if err != nil {
			return nil, RoleMembersOutput{}, fmt.Errorf("list role members: %w", err)
		}
		out := RoleMembersOutput{Members: make([]RoleMemberOutput, 0, len(response.GetMembers()))}
		for _, member := range response.GetMembers() {
			out.Members = append(out.Members, roleMemberOutput(member))
		}
		return nil, out, nil
	})
}

func registerMutationTools(server *mcp.Server, backend Backend) {
	mcp.AddTool(server, additiveTool("create_role", "Create role", "Create a role with zero or more parent roles."), func(ctx context.Context, _ *mcp.CallToolRequest, in CreateRoleInput) (*mcp.CallToolResult, CreateRoleOutput, error) {
		id, err := backend.CreateRole(ctx, in)
		return nil, CreateRoleOutput{RoleID: id}, wrap("create role", err)
	})
	mcp.AddTool(server, destructiveTool("assign_role", "Assign role", "Create or replace a user's membership, level, expiry-free grant, and initial tags."), func(ctx context.Context, _ *mcp.CallToolRequest, in AssignRoleInput) (*mcp.CallToolResult, MutationOutput, error) {
		return mutation("assign role", backend.AssignRole(ctx, in))
	})
	mcp.AddTool(server, destructiveTool("remove_role", "Remove role membership", "Remove one user's direct membership from a role."), func(ctx context.Context, _ *mcp.CallToolRequest, in MembershipInput) (*mcp.CallToolResult, MutationOutput, error) {
		return mutation("remove role membership", backend.RemoveRole(ctx, in))
	})
	mcp.AddTool(server, destructiveTool("ban_user", "Ban user", "Ban a human user and revoke every refresh session. Superusers cannot be banned."), func(ctx context.Context, _ *mcp.CallToolRequest, in BanUserInput) (*mcp.CallToolResult, MutationOutput, error) {
		return mutation("ban user", backend.BanUser(ctx, in))
	})
	mcp.AddTool(server, additiveTool("unban_user", "Unban user", "Restore login for a banned user. Previously issued tokens remain invalid."), func(ctx context.Context, _ *mcp.CallToolRequest, in UserInput) (*mcp.CallToolResult, MutationOutput, error) {
		return mutation("unban user", backend.UnbanUser(ctx, in))
	})
	mcp.AddTool(server, additiveTool("add_role_tag", "Add role tag", "Add one normalized tag definition to a role."), func(ctx context.Context, _ *mcp.CallToolRequest, in RoleTagInput) (*mcp.CallToolResult, MutationOutput, error) {
		return mutation("add role tag", backend.ChangeRoleTag(ctx, in, true))
	})
	mcp.AddTool(server, destructiveTool("delete_role_tag", "Delete role tag", "Disable one role tag definition while preserving membership grants for possible restoration."), func(ctx context.Context, _ *mcp.CallToolRequest, in RoleTagInput) (*mcp.CallToolResult, MutationOutput, error) {
		return mutation("delete role tag", backend.ChangeRoleTag(ctx, in, false))
	})
	mcp.AddTool(server, additiveTool("grant_membership_tag", "Grant membership tag", "Grant one configured tag to one role membership."), func(ctx context.Context, _ *mcp.CallToolRequest, in MembershipTagInput) (*mcp.CallToolResult, MutationOutput, error) {
		return mutation("grant membership tag", backend.ChangeMembershipTag(ctx, in, true))
	})
	mcp.AddTool(server, destructiveTool("revoke_membership_tag", "Revoke membership tag", "Revoke one tag from one role membership."), func(ctx context.Context, _ *mcp.CallToolRequest, in MembershipTagInput) (*mcp.CallToolResult, MutationOutput, error) {
		return mutation("revoke membership tag", backend.ChangeMembershipTag(ctx, in, false))
	})
}

func normalizeList(in ListInput) ListInput {
	if in.PageSize == 0 {
		in.PageSize = 25
	}
	return in
}

func mutation(operation string, err error) (*mcp.CallToolResult, MutationOutput, error) {
	return nil, MutationOutput{Changed: err == nil}, wrap(operation, err)
}

func wrap(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func readTool(name, title, description string) *mcp.Tool {
	return &mcp.Tool{Name: name, Title: title, Description: description, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPointer(false)}}
}

func additiveTool(name, title, description string) *mcp.Tool {
	return &mcp.Tool{Name: name, Title: title, Description: description, Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPointer(false), OpenWorldHint: boolPointer(false)}}
}

func destructiveTool(name, title, description string) *mcp.Tool {
	return &mcp.Tool{Name: name, Title: title, Description: description, Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPointer(true), OpenWorldHint: boolPointer(false)}}
}

func boolPointer(value bool) *bool { return &value }

func userOutput(user *authv1.User) UserOutput {
	out := UserOutput{ID: user.GetId(), Login: user.GetLogin(), Kind: user.GetKind().String(), Superuser: user.GetSuperuser(), BanReason: user.GetBanReason()}
	if user.Email != nil {
		out.Email = user.Email
	}
	out.CreatedAt = timestamp(user.GetCreatedAt())
	if user.GetBannedAt() != nil {
		value := timestamp(user.GetBannedAt())
		out.BannedAt = &value
	}
	return out
}

func roleOutput(role *authv1.Role) RoleOutput {
	return RoleOutput{ID: role.GetId(), Name: role.GetName(), Description: role.GetDescription(), ParentIDs: role.GetParentIds(), Tags: role.GetTags(), CreatedAt: timestamp(role.GetCreatedAt())}
}

func userRoleOutput(role *authv1.UserRole) UserRoleOutput {
	out := UserRoleOutput{ID: role.GetId(), UserID: role.GetUserId(), RoleID: role.GetRoleId(), Level: role.GetLevel().String(), ValidFrom: timestamp(role.GetValidFrom())}
	if role.GetValidUntil() != nil {
		value := timestamp(role.GetValidUntil())
		out.ValidUntil = &value
	}
	if role.GrantedBy != nil {
		out.GrantedBy = role.GrantedBy
	}
	return out
}

func roleMemberOutput(member *authv1.RoleMember) RoleMemberOutput {
	out := RoleMemberOutput{UserID: member.GetUserId(), Login: member.GetLogin(), Level: member.GetLevel().String(), Tags: member.GetTags()}
	if member.Email != nil {
		out.Email = member.Email
	}
	return out
}

func timestamp(value interface{ AsTime() time.Time }) string {
	if value == nil {
		return ""
	}
	return value.AsTime().UTC().Format(time.RFC3339Nano)
}
