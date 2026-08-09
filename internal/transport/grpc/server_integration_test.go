package grpctransport

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/olegkapshai/auth-master/internal/config"
	"github.com/olegkapshai/auth-master/internal/crypto"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/olegkapshai/auth-master/internal/migrate"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/olegkapshai/auth-master/internal/service"
	"github.com/olegkapshai/auth-master/internal/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func grpcIntegrationConfig() *config.Config {
	key := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	return &config.Config{
		PasswordHistoryEncryptionKey: key, SigningKeyMasterKey: key,
		AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, SigningGracePeriod: time.Minute,
		PasswordMaxAge: 365 * 24 * time.Hour, PasswordHistoryN: 5, OTPCodeTTL: time.Minute,
		OTPCodeLength: 6, OTPMaxAttempts: 5, MaxSessionsPerUser: 10, LoginFailWindow: time.Minute,
		LoginFailMax: 10, LoginLockDuration: time.Minute, NotifyOnFailThreshold: 99,
		RegistrationInviteBaseURL: "http://localhost:5173/register",
	}
}

func TestIntegrationGRPCHumanServiceAndTCPJourney(t *testing.T) {
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
	cfg := grpcIntegrationConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auth, err := service.NewAuth(cfg, repo, &mail.Sender{Host: "127.0.0.1", Port: 1025, From: "grpc@test.dev"}, logger)
	require.NoError(t, err)
	require.NoError(t, auth.EnsureBootstrap(ctx))

	passwordHash, err := crypto.HashPassword("Human-Pass1!")
	require.NoError(t, err)
	humanID, err := repo.CreateHumanUser(ctx, "grpc-human", "grpc-human@test.dev", passwordHash)
	require.NoError(t, err)
	require.NoError(t, repo.SetSuperuser(ctx, humanID, true))
	managerID, err := repo.CreateHumanUser(ctx, "grpc-manager", "grpc-manager@test.dev", passwordHash)
	require.NoError(t, err)
	outsiderID, err := repo.CreateHumanUser(ctx, "grpc-outsider", "grpc-outsider@test.dev", passwordHash)
	require.NoError(t, err)
	serviceHash, err := crypto.HashSecret("Service-Secret1!")
	require.NoError(t, err)
	_, err = repo.CreateServiceUser(ctx, "grpc-service", serviceHash, false)
	require.NoError(t, err)

	grpcServer, healthServer := New(auth, repo, logger, Options{})
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveDone := make(chan error, 1)
	go func() { serveDone <- grpcServer.Serve(listener) }()
	t.Cleanup(func() { grpcServer.Stop(); <-serveDone })

	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	healthClient := grpc_health_v1.NewHealthClient(conn)
	healthResponse, err := healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, healthResponse.GetStatus())

	authClient := authv1.NewAuthServiceClient(conn)
	identityClient := authv1.NewIdentityServiceClient(conn)
	adminClient := authv1.NewAdminServiceClient(conn)
	roleClient := authv1.NewRoleServiceClient(conn)
	sessionClient := authv1.NewSessionServiceClient(conn)
	loginWithMagic := func(t *testing.T, userID uuid.UUID, token, device string) *authv1.TokenPair {
		t.Helper()
		_, insertErr := repo.InsertMagicLink(ctx, auth.IntegrationMagicHash(token), userID, time.Now().Add(time.Minute))
		require.NoError(t, insertErr)
		response, loginErr := authClient.CompleteMagicLink(ctx, &authv1.CompleteMagicLinkRequest{Token: token, DeviceId: device})
		require.NoError(t, loginErr)
		require.NotNil(t, response.GetTokens())
		return response.GetTokens()
	}

	_, err = identityClient.GetMe(ctx, &authv1.GetMeRequest{})
	require.Equal(t, codes.Unauthenticated, status.Code(err))

	magicToken := "known-integration-magic-token"
	_, err = repo.InsertMagicLink(ctx, auth.IntegrationMagicHash(magicToken), humanID, time.Now().Add(time.Minute))
	require.NoError(t, err)
	login, err := authClient.CompleteMagicLink(ctx, &authv1.CompleteMagicLinkRequest{Token: magicToken, DeviceId: "grpc-device", DeviceLabel: "integration"})
	require.NoError(t, err)
	require.NotEmpty(t, login.GetTokens().GetAccessToken())
	require.NotEmpty(t, login.GetTokens().GetRefreshToken())
	humanCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+login.GetTokens().GetAccessToken())
	managerTokens := loginWithMagic(t, managerID, "grpc-manager-magic", "manager-device")
	managerCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+managerTokens.GetAccessToken())
	outsiderTokens := loginWithMagic(t, outsiderID, "grpc-outsider-magic", "outsider-device")
	outsiderCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+outsiderTokens.GetAccessToken())
	_, err = adminClient.RotateSigningKey(managerCtx, &authv1.RotateSigningKeyRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))

	me, err := identityClient.GetMe(humanCtx, &authv1.GetMeRequest{})
	require.NoError(t, err)
	require.Equal(t, humanID.String(), me.GetUser().GetId())
	require.Equal(t, authv1.UserKind_USER_KIND_HUMAN, me.GetUser().GetKind())
	require.NotNil(t, me.GetUser().Email)
	require.NoError(t, me.GetUser().GetCreatedAt().CheckValid())
	created, err := roleClient.CreateRole(humanCtx, &authv1.CreateRoleRequest{Name: "grpc-role"})
	require.NoError(t, err)
	require.NotEmpty(t, created.GetRoleId())
	users, err := adminClient.ListUsers(humanCtx, &authv1.ListUsersRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, users.GetUsers())
	require.NotNil(t, users.Total)

	serviceToken, err := authClient.IssueServiceToken(ctx, &authv1.IssueServiceTokenRequest{Login: "grpc-service", Secret: "Service-Secret1!"})
	require.NoError(t, err)
	serviceCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+serviceToken.GetAccessToken())
	_, err = identityClient.GetMe(serviceCtx, &authv1.GetMeRequest{})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	inspected, err := authClient.InspectToken(ctx, &authv1.InspectTokenRequest{Token: serviceToken.GetAccessToken()})
	require.NoError(t, err)
	require.Equal(t, "service", inspected.GetClaims().GetTokenType())
	_, err = authClient.CheckTokenRole(ctx, &authv1.CheckTokenRoleRequest{AccessToken: serviceToken.GetAccessToken(), RoleName: "grpc-role"})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = roleClient.ListRoles(serviceCtx, &authv1.ListRolesRequest{})
	require.NoError(t, err, "RoleService accepts an authenticated service actor")
	_, err = roleClient.CreateRole(serviceCtx, &authv1.CreateRoleRequest{Name: "non-super-service-denied"})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "service authentication must not bypass service-layer authorization")

	createdService, err := adminClient.CreateServiceAccount(humanCtx, &authv1.CreateServiceAccountRequest{
		Login: "grpc-super-service", Secret: "GRPC-Service1!", Superuser: true,
	})
	require.NoError(t, err)
	require.NotEmpty(t, createdService.GetUserId())
	superServiceToken, err := authClient.IssueServiceToken(ctx, &authv1.IssueServiceTokenRequest{Login: "grpc-super-service", Secret: "GRPC-Service1!"})
	require.NoError(t, err)
	superServiceCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+superServiceToken.GetAccessToken())
	serviceCreatedRole, err := roleClient.CreateRole(superServiceCtx, &authv1.CreateRoleRequest{Name: "grpc-service-created-role"})
	require.NoError(t, err)
	require.NotEmpty(t, serviceCreatedRole.GetRoleId())
	createdByService, err := adminClient.CreateServiceAccount(superServiceCtx, &authv1.CreateServiceAccountRequest{
		Login: "grpc-worker-service", Secret: "GRPC-Worker1!",
	})
	require.NoError(t, err)
	require.NotEmpty(t, createdByService.GetUserId())
	_, err = identityClient.GetMe(superServiceCtx, &authv1.GetMeRequest{})
	require.Equal(t, codes.Unauthenticated, status.Code(err), "IdentityService remains human-only")
	_, err = sessionClient.ListSessions(superServiceCtx, &authv1.ListSessionsRequest{})
	require.Equal(t, codes.Unauthenticated, status.Code(err), "SessionService remains human-only")

	_, err = authClient.Refresh(ctx, &authv1.RefreshRequest{RefreshToken: login.GetTokens().GetRefreshToken(), DeviceId: "grpc-device"})
	require.NoError(t, err)

	t.Run("duration contract boundaries", func(t *testing.T) {
		for _, ttl := range []*durationpb.Duration{nil, durationpb.New(0), durationpb.New(time.Nanosecond), durationpb.New(24 * time.Hour)} {
			response, callErr := identityClient.StartStepUp2FA(humanCtx, &authv1.StartStepUp2FARequest{Ttl: ttl})
			require.NoError(t, callErr)
			require.NotEmpty(t, response.GetCorrelationId())
		}
		for _, ttl := range []*durationpb.Duration{durationpb.New(-time.Nanosecond), durationpb.New(24*time.Hour + time.Nanosecond), {Seconds: 9223372037}} {
			_, callErr := identityClient.StartStepUp2FA(humanCtx, &authv1.StartStepUp2FARequest{Ttl: ttl})
			require.Equal(t, codes.InvalidArgument, status.Code(callErr))
		}
		for _, ttl := range []*durationpb.Duration{nil, durationpb.New(0), durationpb.New(time.Nanosecond), durationpb.New(time.Hour)} {
			invite, callErr := adminClient.CreateRegistrationInvite(humanCtx, &authv1.CreateRegistrationInviteRequest{Ttl: ttl})
			require.NoError(t, callErr)
			require.NotEmpty(t, invite.GetToken())
			require.NoError(t, invite.GetExpiresAt().CheckValid())
		}
		for _, ttl := range []*durationpb.Duration{durationpb.New(-time.Nanosecond), {Seconds: 9223372037}} {
			_, callErr := adminClient.CreateRegistrationInvite(humanCtx, &authv1.CreateRegistrationInviteRequest{Ttl: ttl})
			require.Equal(t, codes.InvalidArgument, status.Code(callErr))
		}
	})

	t.Run("authorization actors and persisted role outcomes", func(t *testing.T) {
		parent, callErr := roleClient.CreateRole(humanCtx, &authv1.CreateRoleRequest{Name: "grpc-policy-parent", Description: "parent"})
		require.NoError(t, callErr)
		child, callErr := roleClient.CreateRole(humanCtx, &authv1.CreateRoleRequest{Name: "grpc-policy-child", Description: "child"})
		require.NoError(t, callErr)

		_, callErr = roleClient.ListRoleMembers(outsiderCtx, &authv1.ListRoleMembersRequest{RoleId: parent.GetRoleId()})
		require.Equal(t, codes.PermissionDenied, status.Code(callErr), "non-manager must not list another role's members")
		_, callErr = roleClient.AssignRole(humanCtx, &authv1.AssignRoleRequest{RoleId: parent.GetRoleId(), UserId: managerID.String(), Level: authv1.RoleLevel_ROLE_LEVEL_ROLE_ADMIN})
		require.NoError(t, callErr)
		_, callErr = roleClient.MountRole(managerCtx, &authv1.MountRoleRequest{RoleId: child.GetRoleId(), ParentId: parent.GetRoleId()})
		require.Equal(t, codes.PermissionDenied, status.Code(callErr), "manager must control both mount endpoints")
		_, callErr = roleClient.AssignRole(humanCtx, &authv1.AssignRoleRequest{RoleId: child.GetRoleId(), UserId: managerID.String(), Level: authv1.RoleLevel_ROLE_LEVEL_ROLE_ADMIN})
		require.NoError(t, callErr)
		_, callErr = roleClient.MountRole(managerCtx, &authv1.MountRoleRequest{RoleId: child.GetRoleId(), ParentId: parent.GetRoleId()})
		require.NoError(t, callErr)
		subgroups, callErr := roleClient.ListSubgroups(humanCtx, &authv1.ListSubgroupsRequest{RoleId: parent.GetRoleId(), Recursive: true})
		require.NoError(t, callErr)
		require.Len(t, subgroups.GetRoles(), 1)
		require.Equal(t, child.GetRoleId(), subgroups.GetRoles()[0].GetId())
		require.Contains(t, subgroups.GetRoles()[0].GetParentIds(), parent.GetRoleId())

		_, callErr = roleClient.AddRoleTag(managerCtx, &authv1.AddRoleTagRequest{RoleId: parent.GetRoleId(), Tag: "view"})
		require.NoError(t, callErr)
		validUntil := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		_, callErr = roleClient.AssignRole(managerCtx, &authv1.AssignRoleRequest{RoleId: parent.GetRoleId(), UserId: outsiderID.String(), Level: authv1.RoleLevel_ROLE_LEVEL_MEMBER, ValidUntil: timestamppb.New(validUntil), TagGrants: []string{"view"}})
		require.NoError(t, callErr)

		members, callErr := roleClient.ListRoleMembers(managerCtx, &authv1.ListRoleMembersRequest{RoleId: parent.GetRoleId()})
		require.NoError(t, callErr)
		var outsiderMember *authv1.RoleMember
		for _, member := range members.GetMembers() {
			if member.GetUserId() == outsiderID.String() {
				outsiderMember = member
			}
		}
		require.NotNil(t, outsiderMember)
		require.Equal(t, authv1.RoleLevel_ROLE_LEVEL_MEMBER, outsiderMember.GetLevel())
		require.Contains(t, outsiderMember.GetTags(), "view")

		userRoles, callErr := roleClient.ListUserRoles(outsiderCtx, &authv1.ListUserRolesRequest{UserId: outsiderID.String()})
		require.NoError(t, callErr)
		var parentMembership *authv1.UserRole
		for _, membership := range userRoles.GetUserRoles() {
			if membership.GetRoleId() == parent.GetRoleId() {
				parentMembership = membership
			}
		}
		require.NotNil(t, parentMembership)
		require.Equal(t, authv1.RoleLevel_ROLE_LEVEL_MEMBER, parentMembership.GetLevel())
		require.NotNil(t, parentMembership.ValidUntil)
		require.WithinDuration(t, validUntil, parentMembership.GetValidUntil().AsTime(), time.Second)
		require.NoError(t, parentMembership.GetValidFrom().CheckValid())

		inherited, callErr := identityClient.CheckMyRole(outsiderCtx, &authv1.CheckMyRoleRequest{RoleName: "grpc-policy-child"})
		require.NoError(t, callErr)
		require.True(t, inherited.GetHasRole())
		tagged, callErr := identityClient.CheckMyRoleWithTag(outsiderCtx, &authv1.CheckMyRoleWithTagRequest{RoleName: "grpc-policy-child", Tag: "view"})
		require.NoError(t, callErr)
		require.True(t, tagged.GetHasRoleWithTag())
		access, callErr := identityClient.ListMyRoleAccess(outsiderCtx, &authv1.ListMyRoleAccessRequest{})
		require.NoError(t, callErr)
		require.NotEmpty(t, access.GetRoles())
		for _, item := range access.GetRoles() {
			if item.GetRoleId() == child.GetRoleId() {
				require.False(t, item.GetCanManage())
			}
		}
		crossService, callErr := authClient.CheckTokenRole(humanCtx, &authv1.CheckTokenRoleRequest{AccessToken: outsiderTokens.GetAccessToken(), RoleName: "grpc-policy-child"})
		require.NoError(t, callErr)
		require.True(t, crossService.GetHasRole(), "message token subject, not metadata actor, must be evaluated")

		_, callErr = roleClient.DeleteRoleTag(managerCtx, &authv1.DeleteRoleTagRequest{RoleId: parent.GetRoleId(), Tag: "view"})
		require.NoError(t, callErr)
		tagged, callErr = identityClient.CheckMyRoleWithTag(outsiderCtx, &authv1.CheckMyRoleWithTagRequest{RoleName: "grpc-policy-child", Tag: "view"})
		require.NoError(t, callErr)
		require.False(t, tagged.GetHasRoleWithTag())
		members, callErr = roleClient.ListRoleMembers(managerCtx, &authv1.ListRoleMembersRequest{RoleId: parent.GetRoleId()})
		require.NoError(t, callErr)
		for _, member := range members.GetMembers() {
			if member.GetUserId() == outsiderID.String() {
				require.Contains(t, member.GetTags(), "view", "deleting a definition must preserve its grant")
			}
		}
		_, callErr = roleClient.AddRoleTag(managerCtx, &authv1.AddRoleTagRequest{RoleId: parent.GetRoleId(), Tag: "view"})
		require.NoError(t, callErr)
		tagged, callErr = identityClient.CheckMyRoleWithTag(outsiderCtx, &authv1.CheckMyRoleWithTagRequest{RoleName: "grpc-policy-child", Tag: "view"})
		require.NoError(t, callErr)
		require.True(t, tagged.GetHasRoleWithTag(), "re-adding a definition must restore preserved authorization")

		_, callErr = roleClient.AssignRole(managerCtx, &authv1.AssignRoleRequest{RoleId: parent.GetRoleId(), UserId: outsiderID.String(), Level: authv1.RoleLevel_ROLE_LEVEL_DIRECT_MEMBER, ValidUntil: timestamppb.New(time.Now().Add(-time.Second))})
		require.Equal(t, codes.InvalidArgument, status.Code(callErr))
		userRoles, callErr = roleClient.ListUserRoles(outsiderCtx, &authv1.ListUserRolesRequest{UserId: outsiderID.String()})
		require.NoError(t, callErr)
		for _, membership := range userRoles.GetUserRoles() {
			if membership.GetRoleId() == parent.GetRoleId() {
				require.Equal(t, authv1.RoleLevel_ROLE_LEVEL_MEMBER, membership.GetLevel(), "invalid valid_until must not overwrite membership")
				require.WithinDuration(t, validUntil, membership.GetValidUntil().AsTime(), time.Second)
			}
		}

		firstPage, callErr := roleClient.ListRoles(humanCtx, &authv1.ListRolesRequest{Page: &authv1.PageRequest{PageSize: 1}})
		require.NoError(t, callErr)
		require.Len(t, firstPage.GetRoles(), 1)
		require.NotNil(t, firstPage.Total)
		require.NotEmpty(t, firstPage.GetNextCursor())
		secondPage, callErr := roleClient.ListRoles(humanCtx, &authv1.ListRolesRequest{Page: &authv1.PageRequest{PageSize: 1, Cursor: firstPage.GetNextCursor()}})
		require.NoError(t, callErr)
		require.Len(t, secondPage.GetRoles(), 1)
		require.Nil(t, secondPage.Total)
		require.NotEqual(t, firstPage.GetRoles()[0].GetId(), secondPage.GetRoles()[0].GetId())
	})

	t.Run("role request transitions are single decision", func(t *testing.T) {
		approveRole, callErr := roleClient.CreateRole(humanCtx, &authv1.CreateRoleRequest{Name: "grpc-request-approve"})
		require.NoError(t, callErr)
		_, callErr = roleClient.RequestRole(outsiderCtx, &authv1.RequestRoleRequest{RoleId: approveRole.GetRoleId(), TargetUserId: managerID.String()})
		require.Equal(t, codes.PermissionDenied, status.Code(callErr), "ordinary actors cannot request for another target")
		pending, callErr := roleClient.RequestRole(outsiderCtx, &authv1.RequestRoleRequest{RoleId: approveRole.GetRoleId()})
		require.NoError(t, callErr)
		require.NotEmpty(t, pending.GetPendingRequestId())
		listed, callErr := roleClient.ListRoleRequests(humanCtx, &authv1.ListRoleRequestsRequest{RoleId: approveRole.GetRoleId()})
		require.NoError(t, callErr)
		require.Len(t, listed.GetRequests(), 1)
		require.Equal(t, authv1.RoleRequestStatus_ROLE_REQUEST_STATUS_PENDING, listed.GetRequests()[0].GetStatus())
		require.Equal(t, outsiderID.String(), listed.GetRequests()[0].GetRequesterId())
		require.Equal(t, outsiderID.String(), listed.GetRequests()[0].GetTargetUserId())
		_, callErr = roleClient.DecideRoleRequest(humanCtx, &authv1.DecideRoleRequestRequest{RequestId: pending.GetPendingRequestId(), Approve: true})
		require.NoError(t, callErr)
		_, callErr = roleClient.DecideRoleRequest(humanCtx, &authv1.DecideRoleRequestRequest{RequestId: pending.GetPendingRequestId(), Approve: false})
		require.Equal(t, codes.FailedPrecondition, status.Code(callErr))
		approvedID, parseErr := uuid.Parse(pending.GetPendingRequestId())
		require.NoError(t, parseErr)
		approvedState, callErr := repo.GetRoleRequest(ctx, approvedID)
		require.NoError(t, callErr)
		require.Equal(t, domain.RoleRequestApproved, approvedState.Status)
		require.NotNil(t, approvedState.DecidedBy)
		hasApproved, callErr := identityClient.CheckMyRole(outsiderCtx, &authv1.CheckMyRoleRequest{RoleName: "grpc-request-approve"})
		require.NoError(t, callErr)
		require.True(t, hasApproved.GetHasRole())

		rejectRole, callErr := roleClient.CreateRole(humanCtx, &authv1.CreateRoleRequest{Name: "grpc-request-reject"})
		require.NoError(t, callErr)
		rejected, callErr := roleClient.RequestRole(outsiderCtx, &authv1.RequestRoleRequest{RoleId: rejectRole.GetRoleId()})
		require.NoError(t, callErr)
		_, callErr = roleClient.DecideRoleRequest(humanCtx, &authv1.DecideRoleRequestRequest{RequestId: rejected.GetPendingRequestId(), Approve: false})
		require.NoError(t, callErr)
		_, callErr = roleClient.DecideRoleRequest(humanCtx, &authv1.DecideRoleRequestRequest{RequestId: rejected.GetPendingRequestId(), Approve: false})
		require.Equal(t, codes.FailedPrecondition, status.Code(callErr))
		rejectedID, parseErr := uuid.Parse(rejected.GetPendingRequestId())
		require.NoError(t, parseErr)
		rejectedState, callErr := repo.GetRoleRequest(ctx, rejectedID)
		require.NoError(t, callErr)
		require.Equal(t, domain.RoleRequestRejected, rejectedState.Status)
		hasRejected, callErr := identityClient.CheckMyRole(outsiderCtx, &authv1.CheckMyRoleRequest{RoleName: "grpc-request-reject"})
		require.NoError(t, callErr)
		require.False(t, hasRejected.GetHasRole())
	})

	t.Run("ban revokes existing credentials without resurrection", func(t *testing.T) {
		_, callErr := adminClient.BanUser(humanCtx, &authv1.BanUserRequest{UserId: outsiderID.String(), Reason: "security incident"})
		require.NoError(t, callErr)
		_, callErr = identityClient.GetMe(outsiderCtx, &authv1.GetMeRequest{})
		require.Equal(t, codes.PermissionDenied, status.Code(callErr))
		_, callErr = authClient.Refresh(ctx, &authv1.RefreshRequest{RefreshToken: outsiderTokens.GetRefreshToken(), DeviceId: "outsider-device"})
		require.Equal(t, codes.Unauthenticated, status.Code(callErr))
		users, callErr := adminClient.ListUsers(humanCtx, &authv1.ListUsersRequest{Page: &authv1.PageRequest{Query: "grpc-outsider"}})
		require.NoError(t, callErr)
		require.Len(t, users.GetUsers(), 1)
		require.NotNil(t, users.GetUsers()[0].BannedAt)
		require.Equal(t, "security incident", users.GetUsers()[0].GetBanReason())

		_, callErr = adminClient.UnbanUser(humanCtx, &authv1.UnbanUserRequest{UserId: outsiderID.String()})
		require.NoError(t, callErr)
		_, callErr = identityClient.GetMe(outsiderCtx, &authv1.GetMeRequest{})
		require.Equal(t, codes.Unauthenticated, status.Code(callErr), "unban must not resurrect an access token issued before ban")
		_, callErr = authClient.Refresh(ctx, &authv1.RefreshRequest{RefreshToken: outsiderTokens.GetRefreshToken(), DeviceId: "outsider-device"})
		require.Equal(t, codes.Unauthenticated, status.Code(callErr), "unban must not resurrect a revoked refresh token")
		newTokens := loginWithMagic(t, outsiderID, "grpc-outsider-after-unban", "outsider-device-new")
		newCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+newTokens.GetAccessToken())
		meAfterUnban, callErr := identityClient.GetMe(newCtx, &authv1.GetMeRequest{})
		require.NoError(t, callErr)
		require.Equal(t, outsiderID.String(), meAfterUnban.GetUser().GetId())
		require.Nil(t, meAfterUnban.GetUser().BannedAt)
	})

	t.Run("shared identity session admin and role use cases", func(t *testing.T) {
		_, callErr := authClient.StartMagicLink(ctx, &authv1.StartMagicLinkRequest{Login: "grpc-human"})
		require.NoError(t, callErr)
		passwordStep, callErr := authClient.LoginPassword(ctx, &authv1.LoginPasswordRequest{Login: "grpc-human", Password: "Human-Pass1!"})
		require.NoError(t, callErr)
		require.True(t, passwordStep.GetOtpSent())
		manualChallenge := "grpc-manual-login"
		_, callErr = repo.CreateEmailOTP(ctx, humanID, domain.OTPLogin, auth.IntegrationOTPHash("123456"), time.Now().Add(time.Minute), &manualChallenge)
		require.NoError(t, callErr)
		verified, callErr := authClient.VerifyLoginOTP(ctx, &authv1.VerifyLoginOTPRequest{Challenge: manualChallenge, Code: "123456", DeviceId: "grpc-device-2"})
		require.NoError(t, callErr)
		_, callErr = authClient.VerifyAccessToken(ctx, &authv1.VerifyAccessTokenRequest{AccessToken: verified.GetTokens().GetAccessToken()})
		require.NoError(t, callErr)

		invite, callErr := adminClient.CreateRegistrationInvite(humanCtx, &authv1.CreateRegistrationInviteRequest{Ttl: durationpb.New(time.Hour)})
		require.NoError(t, callErr)
		preview, callErr := authClient.PreviewRegistrationInvite(ctx, &authv1.PreviewRegistrationInviteRequest{Token: invite.GetToken()})
		require.NoError(t, callErr)
		require.True(t, preview.GetValid())
		registered, callErr := authClient.Register(ctx, &authv1.RegisterRequest{InviteToken: invite.GetToken(), Login: "grpc-third", Email: "grpc-third@test.dev", Password: "Third-Pass1!"})
		require.NoError(t, callErr)
		_, callErr = authClient.StartPasswordReset(ctx, &authv1.StartPasswordResetRequest{Login: "grpc-third"})
		require.NoError(t, callErr)
		thirdID, callErr := parseID("user_id", registered.GetUserId())
		require.NoError(t, callErr)
		_, callErr = repo.CreateEmailOTP(ctx, thirdID, domain.OTPPasswordReset, auth.IntegrationOTPHash("556677"), time.Now().Add(time.Minute), nil)
		require.NoError(t, callErr)
		_, callErr = authClient.CompletePasswordReset(ctx, &authv1.CompletePasswordResetRequest{Login: "grpc-third", Code: "556677", NewPassword: "Nebula-Quartz9!"})
		require.NoError(t, callErr)

		parent, callErr := roleClient.CreateRole(humanCtx, &authv1.CreateRoleRequest{Name: "grpc-parent"})
		require.NoError(t, callErr)
		child, callErr := roleClient.CreateRole(humanCtx, &authv1.CreateRoleRequest{Name: "grpc-child"})
		require.NoError(t, callErr)
		_, callErr = roleClient.UpdateRoleDescription(humanCtx, &authv1.UpdateRoleDescriptionRequest{RoleId: child.GetRoleId(), Description: "child role"})
		require.NoError(t, callErr)
		_, callErr = roleClient.ListRoles(humanCtx, &authv1.ListRolesRequest{Page: &authv1.PageRequest{PageSize: 1}})
		require.NoError(t, callErr)
		_, callErr = roleClient.MountRole(humanCtx, &authv1.MountRoleRequest{RoleId: child.GetRoleId(), ParentId: parent.GetRoleId()})
		require.NoError(t, callErr)
		_, callErr = roleClient.ListSubgroups(humanCtx, &authv1.ListSubgroupsRequest{RoleId: parent.GetRoleId(), Recursive: true})
		require.NoError(t, callErr)
		_, callErr = roleClient.UnmountRole(humanCtx, &authv1.UnmountRoleRequest{RoleId: child.GetRoleId(), ParentId: parent.GetRoleId()})
		require.NoError(t, callErr)
		parentID := parent.GetRoleId()
		_, callErr = roleClient.SetRoleParent(humanCtx, &authv1.SetRoleParentRequest{RoleId: child.GetRoleId(), ParentId: &parentID})
		require.NoError(t, callErr)
		_, callErr = roleClient.AddRoleTag(humanCtx, &authv1.AddRoleTagRequest{RoleId: child.GetRoleId(), Tag: "deploy"})
		require.NoError(t, callErr)
		_, callErr = roleClient.RenameRoleTag(humanCtx, &authv1.RenameRoleTagRequest{RoleId: child.GetRoleId(), OldTag: "deploy", NewTag: "release"})
		require.NoError(t, callErr)
		_, callErr = roleClient.AssignRole(humanCtx, &authv1.AssignRoleRequest{RoleId: child.GetRoleId(), UserId: humanID.String(), Level: authv1.RoleLevel_ROLE_LEVEL_ROLE_ADMIN, TagGrants: []string{"release"}})
		require.NoError(t, callErr)
		_, callErr = roleClient.ListRoleMembers(humanCtx, &authv1.ListRoleMembersRequest{RoleId: child.GetRoleId()})
		require.NoError(t, callErr)
		_, callErr = roleClient.ListUserRoles(humanCtx, &authv1.ListUserRolesRequest{UserId: humanID.String()})
		require.NoError(t, callErr)
		_, callErr = roleClient.GrantMembershipTag(humanCtx, &authv1.GrantMembershipTagRequest{RoleId: child.GetRoleId(), UserId: humanID.String(), Tag: "release"})
		require.NoError(t, callErr)
		_, callErr = identityClient.CheckMyRole(humanCtx, &authv1.CheckMyRoleRequest{RoleName: "grpc-child"})
		require.NoError(t, callErr)
		_, callErr = identityClient.CheckMyRoleWithTag(humanCtx, &authv1.CheckMyRoleWithTagRequest{RoleName: "grpc-child", Tag: "release"})
		require.NoError(t, callErr)
		_, callErr = identityClient.ListMyRoleAccess(humanCtx, &authv1.ListMyRoleAccessRequest{})
		require.NoError(t, callErr)
		_, callErr = identityClient.StartPasswordChangeOTP(humanCtx, &authv1.StartPasswordChangeOTPRequest{})
		require.NoError(t, callErr)
		_, callErr = repo.CreateEmailOTP(ctx, humanID, domain.OTPPasswordChange, auth.IntegrationOTPHash("667788"), time.Now().Add(time.Minute), nil)
		require.NoError(t, callErr)
		_, callErr = identityClient.ChangePassword(humanCtx, &authv1.ChangePasswordRequest{OldPassword: "Human-Pass1!", NewPassword: "Orchid-Rocket9!", Code: "667788"})
		require.NoError(t, callErr)
		_, callErr = authClient.CheckTokenRole(ctx, &authv1.CheckTokenRoleRequest{AccessToken: verified.GetTokens().GetAccessToken(), RoleName: "grpc-child"})
		require.NoError(t, callErr)
		_, callErr = authClient.CheckTokenRoleWithTag(ctx, &authv1.CheckTokenRoleWithTagRequest{AccessToken: verified.GetTokens().GetAccessToken(), RoleName: "grpc-child", Tag: "release"})
		require.NoError(t, callErr)
		_, callErr = roleClient.RevokeMembershipTag(humanCtx, &authv1.RevokeMembershipTagRequest{RoleId: child.GetRoleId(), UserId: humanID.String(), Tag: "release"})
		require.NoError(t, callErr)
		_, callErr = roleClient.DeleteRoleTag(humanCtx, &authv1.DeleteRoleTagRequest{RoleId: child.GetRoleId(), Tag: "release"})
		require.NoError(t, callErr)

		stepUp, callErr := identityClient.StartStepUp2FA(humanCtx, &authv1.StartStepUp2FARequest{Ttl: durationpb.New(time.Minute)})
		require.NoError(t, callErr)
		_, callErr = identityClient.GetStepUp2FAStatus(humanCtx, &authv1.GetStepUp2FAStatusRequest{CorrelationId: stepUp.GetCorrelationId()})
		require.NoError(t, callErr)
		_, callErr = identityClient.ExpireStepUp2FA(humanCtx, &authv1.ExpireStepUp2FARequest{CorrelationId: stepUp.GetCorrelationId()})
		require.NoError(t, callErr)
		stepCorrelation := "grpc-complete-step-up"
		require.NoError(t, repo.CreateStepUp2FASession(ctx, stepCorrelation, humanID, time.Now().Add(time.Minute)))
		_, callErr = repo.CreateEmailOTP(ctx, humanID, domain.OTPStepUp2FA, auth.IntegrationOTPHash("334455"), time.Now().Add(time.Minute), &stepCorrelation)
		require.NoError(t, callErr)
		_, callErr = authClient.CompleteStepUp2FA(ctx, &authv1.CompleteStepUp2FARequest{CorrelationId: stepCorrelation, Code: "334455"})
		require.NoError(t, callErr)

		sessions, callErr := sessionClient.ListSessions(humanCtx, &authv1.ListSessionsRequest{})
		require.NoError(t, callErr)
		require.NotEmpty(t, sessions.GetSessions())
		_, callErr = sessionClient.RevokeOwnSession(humanCtx, &authv1.RevokeOwnSessionRequest{SessionId: sessions.GetSessions()[0].GetId()})
		require.NoError(t, callErr)
		_, callErr = sessionClient.StartSessionRevokeOTP(humanCtx, &authv1.StartSessionRevokeOTPRequest{})
		require.NoError(t, callErr)
		_, callErr = repo.CreateEmailOTP(ctx, humanID, domain.OTPSessionRevoke, auth.IntegrationOTPHash("778899"), time.Now().Add(time.Minute), nil)
		require.NoError(t, callErr)
		for _, session := range sessions.GetSessions() {
			if !session.GetRevoked() {
				_, callErr = sessionClient.RevokeSessionWithOTP(humanCtx, &authv1.RevokeSessionWithOTPRequest{SessionId: session.GetId(), Code: "778899"})
				require.NoError(t, callErr)
				break
			}
		}

		_, callErr = roleClient.RequestRole(humanCtx, &authv1.RequestRoleRequest{RoleId: parent.GetRoleId()})
		require.NoError(t, callErr)
		_, callErr = roleClient.ListRoleRequests(humanCtx, &authv1.ListRoleRequestsRequest{RoleId: parent.GetRoleId()})
		require.NoError(t, callErr)
		_, callErr = roleClient.RemoveRole(humanCtx, &authv1.RemoveRoleRequest{RoleId: child.GetRoleId(), UserId: humanID.String()})
		require.NoError(t, callErr)
		_, callErr = roleClient.DeleteRole(humanCtx, &authv1.DeleteRoleRequest{RoleId: child.GetRoleId()})
		require.NoError(t, callErr)

		_, callErr = adminClient.BanUser(humanCtx, &authv1.BanUserRequest{UserId: registered.GetUserId(), Reason: "integration"})
		require.NoError(t, callErr)
		_, callErr = adminClient.UnbanUser(humanCtx, &authv1.UnbanUserRequest{UserId: registered.GetUserId()})
		require.NoError(t, callErr)
		_, callErr = authClient.Logout(ctx, &authv1.LogoutRequest{RefreshToken: verified.GetTokens().GetRefreshToken()})
		require.NoError(t, callErr)
		_, callErr = adminClient.RotateSigningKey(humanCtx, &authv1.RotateSigningKeyRequest{})
		require.NoError(t, callErr)
	})
}
