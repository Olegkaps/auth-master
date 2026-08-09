package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

var safeName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

var storageTags = []string{"read", "write", "admin"}

type registrationInput struct {
	InviteToken string `json:"-"`
	Login       string `json:"login"`
	Email       string `json:"email"`
	Password    string `json:"password"`
}

type authProvisioner interface {
	IssueServiceToken(context.Context, string, string) (string, error)
	CreateInvite(context.Context, string, string) (string, error)
	Register(context.Context, registrationInput) (string, error)
	ProvisionUser(context.Context, string, string) (string, error)
	ProvisionFolder(context.Context, string, string, string) (string, error)
	ListFolderAccess(context.Context, string, string, string) (folderAccess, error)
	CreateGroup(context.Context, string, string, string) (string, error)
	AddGroupMember(context.Context, string, string, string, []string) error
	ShareFolderWithGroup(context.Context, string, string, string, string) error
}

type folderAccess struct {
	Role   string   `json:"role"`
	Groups []string `json:"groups"`
}

type grpcProvisioner struct {
	auth    authv1.AuthServiceClient
	admin   authv1.AdminServiceClient
	roles   authv1.RoleServiceClient
	timeout time.Duration
}

func (p grpcProvisioner) IssueServiceToken(ctx context.Context, login, secret string) (string, error) {
	callCtx, cancel := p.callContext(ctx)
	defer cancel()
	response, err := p.auth.IssueServiceToken(callCtx, &authv1.IssueServiceTokenRequest{Login: login, Secret: secret})
	if err != nil {
		return "", err
	}
	return response.GetAccessToken(), nil
}

func (p grpcProvisioner) CreateInvite(ctx context.Context, actorToken, email string) (string, error) {
	ctx, cancel := p.actorContext(ctx, actorToken)
	defer cancel()
	response, err := p.admin.CreateRegistrationInvite(ctx, &authv1.CreateRegistrationInviteRequest{
		Email: &email,
		Ttl:   durationpb.New(24 * time.Hour),
	})
	if err != nil {
		return "", err
	}
	return response.GetToken(), nil
}

func (p grpcProvisioner) Register(ctx context.Context, input registrationInput) (string, error) {
	callCtx, cancel := p.callContext(ctx)
	defer cancel()
	registered, err := p.auth.Register(callCtx, &authv1.RegisterRequest{
		InviteToken: input.InviteToken,
		Login:       input.Login,
		Email:       input.Email,
		Password:    input.Password,
	})
	if err != nil {
		return "", err
	}
	return registered.GetUserId(), nil
}

func (p grpcProvisioner) ProvisionFolder(ctx context.Context, actorToken, ownerID, folderPath string) (string, error) {
	roleName := folderRoleForPath(ownerID, folderPath)
	roleID, err := p.ensureRole(ctx, actorToken, roleName, "MinIO folder /"+folderPath+" for "+ownerID)
	if err != nil {
		return "", fmt.Errorf("ensure folder role: %w", err)
	}
	if err := p.addTags(ctx, actorToken, roleID); err != nil {
		return "", err
	}
	parentID, err := p.findRoleID(ctx, actorToken, folderRoleForPath(ownerID, parentFolder(folderPath)))
	if err != nil {
		return "", fmt.Errorf("find parent folder role: %w", err)
	}
	callCtx, cancel := p.actorContext(ctx, actorToken)
	defer cancel()
	_, err = p.roles.MountRole(callCtx, &authv1.MountRoleRequest{RoleId: roleID, ParentId: parentID})
	if err != nil && status.Code(err) != codes.AlreadyExists {
		return "", fmt.Errorf("mount folder role: %w", err)
	}
	return roleName, nil
}

func (p grpcProvisioner) ListFolderAccess(ctx context.Context, actorToken, ownerID, folderPath string) (folderAccess, error) {
	roleName := folderRoleForPath(ownerID, folderPath)
	role, err := p.findRole(ctx, actorToken, roleName)
	if err != nil {
		return folderAccess{}, err
	}
	parents := make(map[string]struct{}, len(role.GetParentIds()))
	for _, parentID := range role.GetParentIds() {
		parents[parentID] = struct{}{}
	}
	groups := make([]string, 0)
	cursor := ""
	for {
		callCtx, cancel := p.actorContext(ctx, actorToken)
		response, listErr := p.roles.ListRoles(callCtx, &authv1.ListRolesRequest{Page: &authv1.PageRequest{
			Query: "storage.group.", Cursor: cursor, PageSize: 100,
		}})
		cancel()
		if listErr != nil {
			return folderAccess{}, listErr
		}
		for _, candidate := range response.GetRoles() {
			if _, ok := parents[candidate.GetId()]; ok && strings.HasPrefix(candidate.GetName(), "storage.group.") {
				groups = append(groups, strings.TrimPrefix(candidate.GetName(), "storage.group."))
			}
		}
		cursor = response.GetNextCursor()
		if cursor == "" {
			break
		}
	}
	sort.Strings(groups)
	return folderAccess{Role: roleName, Groups: groups}, nil
}

func (p grpcProvisioner) ProvisionUser(ctx context.Context, actorToken, userID string) (string, error) {
	roleName := folderRole(userID)
	roleID, err := p.ensureRole(ctx, actorToken, roleName, "personal MinIO folder "+userID)
	if err != nil {
		return "", fmt.Errorf("ensure folder role: %w", err)
	}
	if err := p.addTags(ctx, actorToken, roleID); err != nil {
		return "", err
	}
	callCtx, cancel := p.actorContext(ctx, actorToken)
	defer cancel()
	_, err = p.roles.AssignRole(callCtx, &authv1.AssignRoleRequest{
		RoleId:    roleID,
		UserId:    userID,
		Level:     authv1.RoleLevel_ROLE_LEVEL_ROLE_ADMIN,
		TagGrants: append([]string(nil), storageTags...),
	})
	if err != nil {
		return "", fmt.Errorf("assign folder owner: %w", err)
	}
	return roleName, nil
}

func (p grpcProvisioner) CreateGroup(ctx context.Context, actorToken, name, managerUserID string) (string, error) {
	roleName, err := groupRole(name)
	if err != nil {
		return "", err
	}
	roleID, err := p.ensureRole(ctx, actorToken, roleName, "MinIO sharing group "+name)
	if err != nil {
		return "", err
	}
	if err := p.addTags(ctx, actorToken, roleID); err != nil {
		return "", err
	}
	callCtx, cancel := p.actorContext(ctx, actorToken)
	_, err = p.roles.AssignRole(callCtx, &authv1.AssignRoleRequest{
		RoleId: roleID, UserId: managerUserID,
		Level: authv1.RoleLevel_ROLE_LEVEL_ROLE_ADMIN, TagGrants: append([]string(nil), storageTags...),
	})
	cancel()
	if err != nil {
		return "", fmt.Errorf("assign group manager: %w", err)
	}
	return roleName, nil
}

// ensureRole reconciles both an already-existing role and a lost CreateRole
// response. Repeating it after any later partial failure is safe.
func (p grpcProvisioner) ensureRole(ctx context.Context, actorToken, name, description string) (string, error) {
	roleID, err := p.findRoleID(ctx, actorToken, name)
	if err == nil {
		return roleID, nil
	}
	if status.Code(err) != codes.NotFound {
		return "", err
	}
	callCtx, cancel := p.actorContext(ctx, actorToken)
	created, createErr := p.roles.CreateRole(callCtx, &authv1.CreateRoleRequest{Name: name, Description: description})
	cancel()
	if createErr == nil {
		return created.GetRoleId(), nil
	}
	roleID, findErr := p.findRoleID(ctx, actorToken, name)
	if findErr == nil {
		return roleID, nil
	}
	return "", createErr
}

func (p grpcProvisioner) AddGroupMember(ctx context.Context, actorToken, name, userID string, tags []string) error {
	if err := validateTags(tags); err != nil {
		return err
	}
	roleName, err := groupRole(name)
	if err != nil {
		return err
	}
	roleID, err := p.findRoleID(ctx, actorToken, roleName)
	if err != nil {
		return err
	}
	callCtx, cancel := p.actorContext(ctx, actorToken)
	defer cancel()
	_, err = p.roles.AssignRole(callCtx, &authv1.AssignRoleRequest{
		RoleId: roleID, UserId: userID,
		Level: authv1.RoleLevel_ROLE_LEVEL_MEMBER, TagGrants: tags,
	})
	return err
}

func (p grpcProvisioner) ShareFolderWithGroup(ctx context.Context, actorToken, ownerID, folderPath, group string) error {
	groupName, err := groupRole(group)
	if err != nil {
		return err
	}
	folderID, err := p.findRoleID(ctx, actorToken, folderRoleForPath(ownerID, folderPath))
	if err != nil {
		return err
	}
	groupID, err := p.findRoleID(ctx, actorToken, groupName)
	if err != nil {
		return err
	}
	callCtx, cancel := p.actorContext(ctx, actorToken)
	defer cancel()
	_, err = p.roles.MountRole(callCtx, &authv1.MountRoleRequest{
		RoleId: folderID, ParentId: groupID,
	})
	return err
}

func (p grpcProvisioner) addTags(ctx context.Context, actorToken, roleID string) error {
	for _, tag := range storageTags {
		callCtx, cancel := p.actorContext(ctx, actorToken)
		_, err := p.roles.AddRoleTag(callCtx, &authv1.AddRoleTagRequest{RoleId: roleID, Tag: tag})
		cancel()
		if err != nil && status.Code(err) != codes.AlreadyExists {
			return fmt.Errorf("add %s tag: %w", tag, err)
		}
	}
	return nil
}

func (p grpcProvisioner) findRoleID(ctx context.Context, actorToken, name string) (string, error) {
	role, err := p.findRole(ctx, actorToken, name)
	if err != nil {
		return "", err
	}
	return role.GetId(), nil
}

func (p grpcProvisioner) findRole(ctx context.Context, actorToken, name string) (*authv1.Role, error) {
	cursor := ""
	for {
		callCtx, cancel := p.actorContext(ctx, actorToken)
		response, err := p.roles.ListRoles(callCtx, &authv1.ListRolesRequest{Page: &authv1.PageRequest{
			Query: name, Cursor: cursor, PageSize: 100,
		}})
		cancel()
		if err != nil {
			return nil, err
		}
		for _, role := range response.GetRoles() {
			if strings.EqualFold(role.GetName(), name) {
				return role, nil
			}
		}
		cursor = response.GetNextCursor()
		if cursor == "" {
			return nil, status.Errorf(codes.NotFound, "role %q not found", name)
		}
	}
}

func (p grpcProvisioner) actorContext(ctx context.Context, actorToken string) (context.Context, context.CancelFunc) {
	callCtx, cancel := p.callContext(ctx)
	return metadata.AppendToOutgoingContext(callCtx, "authorization", "Bearer "+actorToken), cancel
}

func (p grpcProvisioner) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := p.timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return context.WithTimeout(ctx, timeout)
}

func validateTags(tags []string) error {
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		if tag != "read" && tag != "write" && tag != "admin" {
			return status.Errorf(codes.InvalidArgument, "unsupported storage tag %q", tag)
		}
		if _, exists := seen[tag]; exists {
			return status.Errorf(codes.InvalidArgument, "duplicate storage tag %q", tag)
		}
		seen[tag] = struct{}{}
	}
	return nil
}

func folderRole(ownerID string) string {
	return "storage.folder." + strings.ToLower(ownerID)
}

func folderRoleForPath(ownerID, folderPath string) string {
	if folderPath == "" {
		return folderRole(ownerID)
	}
	digest := sha256.Sum256([]byte(folderPath))
	return folderRole(ownerID) + "." + hex.EncodeToString(digest[:16])
}

func groupRole(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !safeName.MatchString(name) {
		return "", fmt.Errorf("group name must match %s", safeName)
	}
	return "storage.group." + name, nil
}
