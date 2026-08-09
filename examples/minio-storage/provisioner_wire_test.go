package main

import (
	"context"
	"net"
	"testing"

	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestGRPCProvisioningReconcilesAndPreservesRoleSemantics(t *testing.T) {
	fake := &roleWireFake{roles: make(map[string]string), tags: make(map[string]map[string]bool), loseGroupCreateResponse: true, failFirstManagerAssignment: true}
	connection := startRoleWire(t, fake)
	provisioner := grpcProvisioner{auth: authv1.NewAuthServiceClient(connection), roles: authv1.NewRoleServiceClient(connection)}

	roleName, err := provisioner.ProvisionUser(t.Context(), "operator-token", testUserID)
	require.NoError(t, err)
	require.Equal(t, folderRole(testUserID), roleName)
	require.Equal(t, authv1.RoleLevel_ROLE_LEVEL_ROLE_ADMIN, fake.assignment.GetLevel())
	require.ElementsMatch(t, storageTags, fake.assignment.GetTagGrants())
	require.Equal(t, testUserID, fake.assignment.GetUserId())
	folderID := fake.roles[folderRole(testUserID)]
	require.Equal(t, folderID, fake.assignment.GetRoleId())
	require.ElementsMatch(t, storageTags, mapKeys(fake.tags[folderID]))

	projectRole, err := provisioner.ProvisionFolder(t.Context(), "operator-token", testUserID, "projects")
	require.NoError(t, err)
	require.Equal(t, folderRoleForPath(testUserID, "projects"), projectRole)
	require.Equal(t, fake.roles[projectRole], fake.mount.GetRoleId())
	require.Equal(t, folderID, fake.mount.GetParentId(), "child folder role must mount below its canonical parent")
	childRole, err := provisioner.ProvisionFolder(t.Context(), "operator-token", testUserID, "projects/private")
	require.NoError(t, err)
	require.Equal(t, folderRoleForPath(testUserID, "projects/private"), childRole)
	require.Equal(t, fake.roles[childRole], fake.mount.GetRoleId())
	require.Equal(t, fake.roles[projectRole], fake.mount.GetParentId())

	managerID := "f747986c-f8a1-4dc1-834d-043c8c3f9fe5"
	_, err = provisioner.CreateGroup(t.Context(), "operator-token", "team", managerID)
	require.Error(t, err, "first manager assignment failure must surface for reconciliation")
	groupName, err := provisioner.CreateGroup(t.Context(), "operator-token", "team", managerID)
	require.NoError(t, err)
	require.Equal(t, "storage.group.team", groupName)
	require.ElementsMatch(t, storageTags, mapKeys(fake.tags[fake.roles[groupName]]))
	require.Equal(t, fake.roles[groupName], fake.groupManagerAssignment.GetRoleId())
	require.Equal(t, managerID, fake.groupManagerAssignment.GetUserId())
	require.Equal(t, authv1.RoleLevel_ROLE_LEVEL_ROLE_ADMIN, fake.groupManagerAssignment.GetLevel())
	require.ElementsMatch(t, storageTags, fake.groupManagerAssignment.GetTagGrants())
	memberID := "f17b177c-d8e4-4169-a6ec-a75fb2c6d094"
	memberTags := []string{"read", "write"}
	require.NoError(t, provisioner.AddGroupMember(t.Context(), "operator-token", "team", memberID, memberTags))
	require.Equal(t, fake.roles[groupName], fake.groupAssignment.GetRoleId())
	require.Equal(t, memberID, fake.groupAssignment.GetUserId())
	require.Equal(t, authv1.RoleLevel_ROLE_LEVEL_MEMBER, fake.groupAssignment.GetLevel())
	require.ElementsMatch(t, memberTags, fake.groupAssignment.GetTagGrants())

	require.NoError(t, provisioner.ShareFolderWithGroup(t.Context(), "operator-token", testUserID, "projects", "team"))
	require.Equal(t, fake.roles[projectRole], fake.mount.GetRoleId())
	require.Equal(t, fake.roles[groupName], fake.mount.GetParentId(), "folder must be the child and group the parent")
	require.GreaterOrEqual(t, fake.metadataChecks, 1)
}

func TestListFolderAccessPaginatesAndKeepsOnlyDirectGroupParents(t *testing.T) {
	folderName := folderRoleForPath(testUserID, "projects")
	fake := &roleWireFake{
		roles:            make(map[string]string),
		tags:             make(map[string]map[string]bool),
		accessFolderName: folderName,
		accessFolderID:   "folder-id",
		accessParentIDs:  []string{"group-beta", "not-a-group", "group-alpha"},
	}
	connection := startRoleWire(t, fake)
	provisioner := grpcProvisioner{roles: authv1.NewRoleServiceClient(connection)}

	access, err := provisioner.ListFolderAccess(t.Context(), "operator-token", testUserID, "projects")
	require.NoError(t, err)
	require.Equal(t, folderName, access.Role)
	require.Equal(t, []string{"alpha", "beta"}, access.Groups)
	require.Equal(t, []string{"", "second-page"}, fake.accessCursors)
}

type roleWireFake struct {
	roles                      map[string]string
	tags                       map[string]map[string]bool
	assignment                 *authv1.AssignRoleRequest
	groupAssignment            *authv1.AssignRoleRequest
	groupManagerAssignment     *authv1.AssignRoleRequest
	mount                      *authv1.MountRoleRequest
	metadataChecks             int
	loseGroupCreateResponse    bool
	failFirstManagerAssignment bool
	accessFolderName           string
	accessFolderID             string
	accessParentIDs            []string
	accessCursors              []string
}

func (f *roleWireFake) authorize(ctx context.Context) error {
	values := metadata.ValueFromIncomingContext(ctx, "authorization")
	if len(values) != 1 || values[0] != "Bearer operator-token" {
		return status.Error(codes.Unauthenticated, "missing actor")
	}
	if _, ok := ctx.Deadline(); !ok {
		return status.Error(codes.InvalidArgument, "missing deadline")
	}
	f.metadataChecks++
	return nil
}

func (f *roleWireFake) list(ctx context.Context, input *authv1.ListRolesRequest) (*authv1.ListRolesResponse, error) {
	if err := f.authorize(ctx); err != nil {
		return nil, err
	}
	name := input.GetPage().GetQuery()
	if name == f.accessFolderName && name != "" {
		return &authv1.ListRolesResponse{Roles: []*authv1.Role{{
			Id: f.accessFolderID, Name: name, ParentIds: f.accessParentIDs,
		}}}, nil
	}
	if name == "storage.group." && f.accessFolderName != "" {
		cursor := input.GetPage().GetCursor()
		f.accessCursors = append(f.accessCursors, cursor)
		if cursor == "" {
			return &authv1.ListRolesResponse{
				Roles: []*authv1.Role{
					{Id: "group-beta", Name: "storage.group.beta"},
					{Id: "other-group", Name: "storage.group.unrelated"},
				},
				NextCursor: "second-page",
			}, nil
		}
		return &authv1.ListRolesResponse{Roles: []*authv1.Role{
			{Id: "group-alpha", Name: "storage.group.alpha"},
			{Id: "not-a-group", Name: "storage.audit"},
		}}, nil
	}
	id, ok := f.roles[name]
	if !ok {
		return &authv1.ListRolesResponse{}, nil
	}
	return &authv1.ListRolesResponse{Roles: []*authv1.Role{{Id: id, Name: name}}}, nil
}

func (f *roleWireFake) create(ctx context.Context, input *authv1.CreateRoleRequest) (*authv1.CreateRoleResponse, error) {
	if err := f.authorize(ctx); err != nil {
		return nil, err
	}
	if id, ok := f.roles[input.GetName()]; ok {
		return nil, status.Errorf(codes.AlreadyExists, "role %s exists as %s", input.GetName(), id)
	}
	id := "id-" + input.GetName()
	f.roles[input.GetName()] = id
	f.tags[id] = make(map[string]bool)
	if input.GetName() == "storage.group.team" && f.loseGroupCreateResponse {
		f.loseGroupCreateResponse = false
		return nil, status.Error(codes.Unavailable, "response lost")
	}
	return &authv1.CreateRoleResponse{RoleId: id}, nil
}

func (f *roleWireFake) addTag(ctx context.Context, input *authv1.AddRoleTagRequest) (*emptypb.Empty, error) {
	if err := f.authorize(ctx); err != nil {
		return nil, err
	}
	if f.tags[input.GetRoleId()][input.GetTag()] {
		return nil, status.Error(codes.AlreadyExists, "tag exists")
	}
	f.tags[input.GetRoleId()][input.GetTag()] = true
	return &emptypb.Empty{}, nil
}

func startRoleWire(t *testing.T, fake *roleWireFake) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{ServiceName: "auth.v1.AuthService", HandlerType: (*interface{})(nil), Methods: []grpc.MethodDesc{
		{MethodName: "VerifyAccessToken", Handler: roleUnary(func(_ context.Context, input *authv1.VerifyAccessTokenRequest) (*authv1.VerifyAccessTokenResponse, error) {
			require.Equal(t, "operator-token", input.GetAccessToken())
			return &authv1.VerifyAccessTokenResponse{Claims: &authv1.TokenClaims{Subject: "operator-user-id"}}, nil
		})},
	}}, struct{}{})
	server.RegisterService(&grpc.ServiceDesc{ServiceName: "auth.v1.RoleService", HandlerType: (*interface{})(nil), Methods: []grpc.MethodDesc{
		{MethodName: "ListRoles", Handler: roleUnary(fake.list)},
		{MethodName: "CreateRole", Handler: roleUnary(fake.create)},
		{MethodName: "AddRoleTag", Handler: roleUnary(fake.addTag)},
		{MethodName: "AssignRole", Handler: roleUnary(func(ctx context.Context, input *authv1.AssignRoleRequest) (*emptypb.Empty, error) {
			if err := fake.authorize(ctx); err != nil {
				return nil, err
			}
			if input.GetUserId() == testUserID {
				fake.assignment = input
			} else if input.GetRoleId() == fake.roles["storage.group.team"] && input.GetLevel() == authv1.RoleLevel_ROLE_LEVEL_ROLE_ADMIN {
				if fake.failFirstManagerAssignment {
					fake.failFirstManagerAssignment = false
					return nil, status.Error(codes.Unavailable, "manager assignment response lost")
				}
				fake.groupManagerAssignment = input
			} else {
				fake.groupAssignment = input
			}
			return &emptypb.Empty{}, nil
		})},
		{MethodName: "MountRole", Handler: roleUnary(func(ctx context.Context, input *authv1.MountRoleRequest) (*emptypb.Empty, error) {
			if err := fake.authorize(ctx); err != nil {
				return nil, err
			}
			fake.mount = input
			return &emptypb.Empty{}, nil
		})},
	}}, struct{}{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	connection, err := grpc.NewClient("passthrough:///roles", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func roleUnary[Request any, Response any](method func(context.Context, *Request) (*Response, error)) grpc.MethodHandler {
	return func(_ any, ctx context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
		input := new(Request)
		if err := decode(input); err != nil {
			return nil, err
		}
		return method(ctx, input)
	}
}

func mapKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	return result
}
