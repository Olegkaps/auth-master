package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/olegkapshai/auth-master/examples/internal/authz"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

type subjectVerifierFunc func(context.Context, string) (string, error)

func (f subjectVerifierFunc) VerifySubject(ctx context.Context, token string) (string, error) {
	return f(ctx, token)
}

func TestSupportDeskGRPCWireAuthorization(t *testing.T) {
	authConn := startFakeAuth(t)
	checker := authz.GRPCChecker{Client: authv1.NewAuthServiceClient(authConn), Timeout: time.Second}
	supportConn := startSupport(t, &supportServer{verifier: checker, checker: checker, store: newTicketStore()})
	created := invoke(t, supportConn, "CreateTicket", map[string]any{"access_token": "owner", "body": "printer is on fire"})
	id := created.GetFields()["id"].GetStringValue()
	require.NotEmpty(t, id)
	for _, token := range []string{"owner", "agent", "admin"} {
		response := invoke(t, supportConn, "GetTicket", map[string]any{"access_token": token, "ticket_id": id})
		require.Equal(t, "owner-id", response.GetFields()["owner_id"].GetStringValue())
	}
	input, _ := structpb.NewStruct(map[string]any{"access_token": "stranger", "ticket_id": id})
	err := supportConn.Invoke(t.Context(), "/"+supportServiceName+"/GetTicket", input, new(structpb.Struct))
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestSupportDeskAuthenticatesBeforeTicketLookup(t *testing.T) {
	authConn := startFakeAuth(t)
	checker := authz.GRPCChecker{Client: authv1.NewAuthServiceClient(authConn), Timeout: time.Second}
	store := newTicketStore()
	existing := store.create("owner-id", "existing")
	supportConn := startSupport(t, &supportServer{verifier: checker, checker: checker, store: store})
	missingID := "d53eeb8e-f14f-4642-b62e-c5183174d322"
	for _, fields := range []map[string]any{
		{"ticket_id": missingID},
		{"ticket_id": existing.ID},
		{"access_token": "invalid", "ticket_id": missingID},
		{"access_token": "invalid", "ticket_id": existing.ID},
		{"access_token": "invalid", "ticket_id": "malformed"},
	} {
		input, err := structpb.NewStruct(fields)
		require.NoError(t, err)
		err = supportConn.Invoke(t.Context(), "/"+supportServiceName+"/GetTicket", input, new(structpb.Struct))
		require.Equal(t, codes.Unauthenticated, status.Code(err), "%v", fields)
	}
	input, _ := structpb.NewStruct(map[string]any{"access_token": "owner", "ticket_id": "malformed"})
	err := supportConn.Invoke(t.Context(), "/"+supportServiceName+"/GetTicket", input, new(structpb.Struct))
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestCreateTicketFixtureKeyIsIdempotent(t *testing.T) {
	store := newTicketStore()
	server := &supportServer{
		verifier: subjectVerifierFunc(func(context.Context, string) (string, error) { return "owner-id", nil }),
		store:    store,
	}
	input, err := structpb.NewStruct(map[string]any{"access_token": "owner", "body": "seeded", "fixture_key": "welcome"})
	require.NoError(t, err)
	first, err := server.createTicket(t.Context(), input)
	require.NoError(t, err)
	second, err := server.createTicket(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, first.AsMap()["id"], second.AsMap()["id"])
	require.Len(t, store.seededTickets(), 1)
}

func TestSupportDeskNormalizesVerifierFailureBeforeLookup(t *testing.T) {
	server := &supportServer{
		verifier: subjectVerifierFunc(func(context.Context, string) (string, error) {
			return "", status.Error(codes.Unauthenticated, "upstream detail must not escape")
		}),
		store: nil,
	}

	for _, id := range []string{"70c4c1df-9ff6-4d0c-a7c4-2b4e693ff158", "d53eeb8e-f14f-4642-b62e-c5183174d322"} {
		input, err := structpb.NewStruct(map[string]any{"access_token": "opaque-token", "ticket_id": id})
		require.NoError(t, err)
		_, err = server.getTicket(t.Context(), input)
		require.Equal(t, codes.Unauthenticated, status.Code(err))
		require.Equal(t, "invalid access token", status.Convert(err).Message())
		require.NotContains(t, err.Error(), "upstream detail")
	}
}

func TestSupportDeskNormalizesVerifierFailureOverGRPC(t *testing.T) {
	authConn := startFakeAuth(t)
	checker := authz.GRPCChecker{Client: authv1.NewAuthServiceClient(authConn), Timeout: time.Second}
	supportConn := startSupport(t, &supportServer{verifier: checker, checker: checker, store: nil})

	requests := []struct {
		method string
		fields map[string]any
	}{
		{method: "CreateTicket", fields: map[string]any{"access_token": "backend-failure", "body": "must not be created"}},
		{method: "GetTicket", fields: map[string]any{"access_token": "backend-failure", "ticket_id": "70c4c1df-9ff6-4d0c-a7c4-2b4e693ff158"}},
		{method: "GetTicket", fields: map[string]any{"access_token": "backend-failure", "ticket_id": "d53eeb8e-f14f-4642-b62e-c5183174d322"}},
	}
	for _, request := range requests {
		input, err := structpb.NewStruct(request.fields)
		require.NoError(t, err)
		err = supportConn.Invoke(t.Context(), "/"+supportServiceName+"/"+request.method, input, new(structpb.Struct))
		require.Equal(t, codes.Unavailable, status.Code(err))
		require.Equal(t, "authentication service unavailable", status.Convert(err).Message())
		require.NotContains(t, err.Error(), "database host")
	}
}

func TestSupportDeskPreservesCanonicalVerifierFailureClasses(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code codes.Code
		text string
	}{
		{name: "unauthenticated", err: status.Error(codes.Unauthenticated, "credential detail"), code: codes.Unauthenticated, text: "invalid access token"},
		{name: "internal", err: status.Error(codes.Internal, "database detail"), code: codes.Unavailable, text: "authentication service unavailable"},
		{name: "unavailable", err: status.Error(codes.Unavailable, "dial detail"), code: codes.Unavailable, text: "authentication service unavailable"},
		{name: "unknown", err: errors.New("implementation detail"), code: codes.Unavailable, text: "authentication service unavailable"},
		{name: "deadline", err: context.DeadlineExceeded, code: codes.DeadlineExceeded, text: "authentication deadline exceeded"},
		{name: "canceled", err: context.Canceled, code: codes.Canceled, text: "authentication canceled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &supportServer{verifier: subjectVerifierFunc(func(context.Context, string) (string, error) {
				return "", tt.err
			})}
			_, err := server.verifiedSubject(t.Context(), "opaque-token")
			require.Equal(t, tt.code, status.Code(err))
			require.Equal(t, tt.text, status.Convert(err).Message())
			require.NotContains(t, err.Error(), status.Convert(tt.err).Message())
		})
	}
}

func TestSupportDeskRejectsEmptyVerifiedSubject(t *testing.T) {
	server := &supportServer{verifier: subjectVerifierFunc(func(context.Context, string) (string, error) {
		return "", nil
	})}

	_, err := server.verifiedSubject(t.Context(), "opaque-token")
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	require.Equal(t, "invalid access token", status.Convert(err).Message())
}

func invoke(t *testing.T, connection *grpc.ClientConn, method string, fields map[string]any) *structpb.Struct {
	t.Helper()
	input, err := structpb.NewStruct(fields)
	require.NoError(t, err)
	output := new(structpb.Struct)
	require.NoError(t, connection.Invoke(t.Context(), "/"+supportServiceName+"/"+method, input, output))
	return output
}

func startSupport(t *testing.T, implementation *supportServer) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	registerSupportService(server, implementation)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	connection, err := grpc.NewClient("passthrough:///support", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func startFakeAuth(t *testing.T) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{ServiceName: "auth.v1.AuthService", HandlerType: (*interface{})(nil), Methods: []grpc.MethodDesc{
		{MethodName: "VerifyAccessToken", Handler: verifyHandler}, {MethodName: "CheckTokenRole", Handler: roleHandler},
	}}, struct{}{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	connection, err := grpc.NewClient("passthrough:///auth", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func verifyHandler(_ any, _ context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
	input := new(authv1.VerifyAccessTokenRequest)
	if err := decode(input); err != nil {
		return nil, err
	}
	if input.GetAccessToken() == "invalid" {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if input.GetAccessToken() == "backend-failure" {
		return nil, status.Error(codes.Internal, "database host and JWT detail")
	}
	return &authv1.VerifyAccessTokenResponse{Claims: &authv1.TokenClaims{Subject: input.GetAccessToken() + "-id"}}, nil
}

func roleHandler(_ any, _ context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
	input := new(authv1.CheckTokenRoleRequest)
	if err := decode(input); err != nil {
		return nil, err
	}
	allowed := input.GetAccessToken() == "admin" && input.GetRoleName() == "support.admin" || input.GetAccessToken() == "agent" && input.GetRoleName() == "support.agent"
	return &authv1.HasRoleResponse{HasRole: allowed}, nil
}
