package grpctransport

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/olegkapshai/auth-master/internal/service"
	"github.com/olegkapshai/auth-master/internal/transport/parity"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestAllApplicationRPCsAreUnaryAndClassified(t *testing.T) {
	services := authv1.File_api_auth_v1_auth_proto.Services()
	require.Equal(t, 5, services.Len())
	total := 0
	for i := 0; i < services.Len(); i++ {
		serviceDescriptor := services.Get(i)
		for j := 0; j < serviceDescriptor.Methods().Len(); j++ {
			method := serviceDescriptor.Methods().Get(j)
			require.False(t, method.IsStreamingClient())
			require.False(t, method.IsStreamingServer())
			fullMethod := "/" + string(serviceDescriptor.FullName()) + "/" + string(method.Name())
			policy, classified := parity.RPCPolicies[fullMethod]
			require.Truef(t, classified, "unclassified method %s", fullMethod)
			require.Contains(t, []parity.AuthPolicy{parity.AuthPublic, parity.AuthHuman, parity.AuthActor}, policy)
			total++
		}
	}
	require.Equal(t, 55, total)
	require.Len(t, parity.RPCPolicies, total)
}

func TestAuthInterceptorDefaultsToDenyAndRequiresClassifiedBearer(t *testing.T) {
	server := &Server{}
	called := false
	handler := func(context.Context, any) (any, error) { called = true; return struct{}{}, nil }

	_, err := server.authInterceptor(false)(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/auth.v1.FutureService/Unsafe"}, handler)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.False(t, called)

	_, err = server.authInterceptor(false)(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/auth.v1.IdentityService/FutureUnsafe"}, handler)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.False(t, called)
	_, err = server.authInterceptor(false)(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/auth.v1.AuthService/FuturePublic"}, handler)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.False(t, called)

	_, err = server.authInterceptor(false)(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: authv1.IdentityService_GetMe_FullMethodName}, handler)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	require.False(t, called)
}

func TestIdentityAndSessionStayHumanWhileAdminAndRoleAcceptActors(t *testing.T) {
	require.Equal(t, parity.AuthHuman, parity.RPCPolicies[authv1.IdentityService_GetMe_FullMethodName])
	require.Equal(t, parity.AuthHuman, parity.RPCPolicies[authv1.SessionService_ListSessions_FullMethodName])
	require.Equal(t, parity.AuthActor, parity.RPCPolicies[authv1.AdminService_CreateServiceAccount_FullMethodName])
	require.Equal(t, parity.AuthActor, parity.RPCPolicies[authv1.RoleService_CreateRole_FullMethodName])
}

func TestAuthInterceptorRejectsMalformedBearerMetadata(t *testing.T) {
	server := &Server{}
	handler := func(context.Context, any) (any, error) { return struct{}{}, nil }
	tests := []struct {
		name   string
		values []string
	}{
		{"empty", []string{""}},
		{"empty_token", []string{"Bearer "}},
		{"wrong_scheme", []string{"Basic token"}},
		{"lowercase_scheme", []string{"bearer token"}},
		{"leading_space", []string{" Bearer token"}},
		{"trailing_space", []string{"Bearer token "}},
		{"embedded_space", []string{"Bearer token token"}},
		{"multiple", []string{"Bearer one", "Bearer two"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{"authorization": test.values})
			_, err := server.authInterceptor(false)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: authv1.IdentityService_GetMe_FullMethodName}, handler)
			require.Equal(t, codes.Unauthenticated, status.Code(err))
		})
	}
}

type testServerStream struct{ ctx context.Context }

func (s *testServerStream) SetHeader(metadata.MD) error  { return nil }
func (s *testServerStream) SendHeader(metadata.MD) error { return nil }
func (s *testServerStream) SetTrailer(metadata.MD)       {}
func (s *testServerStream) Context() context.Context     { return s.ctx }
func (s *testServerStream) SendMsg(any) error            { return nil }
func (s *testServerStream) RecvMsg(any) error            { return nil }

func TestStreamInterceptorsDefaultDenyAndClassifyInfrastructure(t *testing.T) {
	server := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	stream := &testServerStream{ctx: context.Background()}
	called := false
	handler := func(any, grpc.ServerStream) error { called = true; return nil }

	err := server.authStreamInterceptor(false)(nil, stream, &grpc.StreamServerInfo{FullMethod: "/auth.v1.RoleService/FutureStream"}, handler)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.False(t, called)

	err = server.authStreamInterceptor(false)(nil, stream, &grpc.StreamServerInfo{FullMethod: grpc_health_v1.Health_Watch_FullMethodName, IsServerStream: true}, handler)
	require.NoError(t, err)
	require.True(t, called)

	called = false
	err = server.authStreamInterceptor(false)(nil, stream, &grpc.StreamServerInfo{FullMethod: "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", IsClientStream: true, IsServerStream: true}, handler)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.False(t, called)
	err = server.authStreamInterceptor(true)(nil, stream, &grpc.StreamServerInfo{FullMethod: "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", IsClientStream: true, IsServerStream: true}, handler)
	require.NoError(t, err)
	require.True(t, called)

	marker := &struct{}{}
	stream.ctx = context.WithValue(context.Background(), marker, "present")
	err = server.authStreamInterceptor(false)(nil, stream, &grpc.StreamServerInfo{FullMethod: grpc_health_v1.Health_Watch_FullMethodName}, func(_ any, wrapped grpc.ServerStream) error {
		require.Equal(t, "present", wrapped.Context().Value(marker))
		return nil
	})
	require.NoError(t, err)

	err = server.recoveryStreamInterceptor(nil, stream, &grpc.StreamServerInfo{FullMethod: grpc_health_v1.Health_Watch_FullMethodName}, func(any, grpc.ServerStream) error {
		panic("secret panic")
	})
	require.Equal(t, codes.Internal, status.Code(err))
	err = errorStreamInterceptor(nil, stream, &grpc.StreamServerInfo{}, func(any, grpc.ServerStream) error { return service.ErrRequestNotPending })
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestErrorMappingIsStableAndPreservesContext(t *testing.T) {
	tests := []struct {
		err    error
		code   codes.Code
		reason string
	}{
		{service.ErrInvalidCredentials, codes.Unauthenticated, "INVALID_CREDENTIAL"},
		{service.ErrBanned, codes.PermissionDenied, "FORBIDDEN"},
		{service.ErrLocked, codes.FailedPrecondition, "ACCOUNT_LOCKED"},
		{service.ErrNotFound, codes.NotFound, "NOT_FOUND"},
		{service.ErrPasswordPolicy, codes.InvalidArgument, "INVALID_ARGUMENT"},
		{service.ErrInvalidArgument, codes.InvalidArgument, "INVALID_ARGUMENT"},
		{service.ErrRequestNotPending, codes.FailedPrecondition, "REQUEST_NOT_PENDING"},
	}
	for _, test := range tests {
		t.Run(test.reason, func(t *testing.T) {
			mapped := mapError(test.err)
			st := status.Convert(mapped)
			require.Equal(t, test.code, st.Code())
			if test.reason != "INVALID_ARGUMENT" {
				require.NotContains(t, st.Message(), "password")
			}
			var detail *errdetails.ErrorInfo
			for _, item := range st.Details() {
				if value, ok := item.(*errdetails.ErrorInfo); ok {
					detail = value
				}
			}
			require.NotNil(t, detail)
			require.Equal(t, test.reason, detail.Reason)
			require.Equal(t, errorDomain, detail.Domain)
		})
	}
	require.Equal(t, codes.Canceled, status.Code(mapError(context.Canceled)))
	require.Equal(t, codes.DeadlineExceeded, status.Code(mapError(context.DeadlineExceeded)))
	require.Equal(t, codes.AlreadyExists, status.Code(mapError(&pgconn.PgError{Code: "23505"})))
	require.Equal(t, codes.FailedPrecondition, status.Code(mapError(&pgconn.PgError{Code: "23503"})))
	require.Equal(t, codes.Aborted, status.Code(mapError(&pgconn.PgError{Code: "40001"})))
}

func TestPageAndCursorValidation(t *testing.T) {
	query, cursor, size, err := page(nil)
	require.NoError(t, err)
	require.Empty(t, query)
	require.Nil(t, cursor)
	require.Equal(t, 25, size)
	_, _, _, err = page(&authv1.PageRequest{PageSize: 101})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, _, _, err = page(&authv1.PageRequest{Cursor: "not-a-cursor"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestReflectionDisabledByDefault(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, _ := New(nil, nil, logger, Options{})
	_, found := server.GetServiceInfo()["grpc.reflection.v1.ServerReflection"]
	require.False(t, found)
	server.Stop()
}
