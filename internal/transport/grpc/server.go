package grpctransport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/olegkapshai/auth-master/internal/jwtutil"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/olegkapshai/auth-master/internal/service"
	"github.com/olegkapshai/auth-master/internal/transport/parity"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	reflectionv1 "google.golang.org/grpc/reflection/grpc_reflection_v1"
	reflectionv1alpha "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
)

const errorDomain = "auth-master"

type actorKey struct{}

// Server implements all five auth.v1 services over the same service and repository
// instances as the HTTP transport.
type Server struct {
	auth *service.Auth
	repo repository.Repository
	log  *slog.Logger
}

type Options struct {
	Reflection     bool
	MaxReceiveSize int
	MaxSendSize    int
	Credentials    credentials.TransportCredentials
}

func New(auth *service.Auth, repo repository.Repository, log *slog.Logger, opts Options) (*grpc.Server, *health.Server) {
	impl := &Server{auth: auth, repo: repo, log: log}
	serverOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(impl.recoveryInterceptor, impl.authInterceptor(opts.Reflection), errorInterceptor),
		grpc.ChainStreamInterceptor(impl.recoveryStreamInterceptor, impl.authStreamInterceptor(opts.Reflection), errorStreamInterceptor),
	}
	if opts.MaxReceiveSize > 0 {
		serverOpts = append(serverOpts, grpc.MaxRecvMsgSize(opts.MaxReceiveSize))
	}
	if opts.MaxSendSize > 0 {
		serverOpts = append(serverOpts, grpc.MaxSendMsgSize(opts.MaxSendSize))
	}
	if opts.Credentials != nil {
		serverOpts = append(serverOpts, grpc.Creds(opts.Credentials))
	}
	g := grpc.NewServer(serverOpts...)
	authv1.RegisterAuthServiceServer(g, impl)
	authv1.RegisterIdentityServiceServer(g, impl)
	authv1.RegisterSessionServiceServer(g, impl)
	authv1.RegisterAdminServiceServer(g, impl)
	authv1.RegisterRoleServiceServer(g, impl)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	grpc_health_v1.RegisterHealthServer(g, healthServer)
	if opts.Reflection {
		reflection.Register(g)
	}
	return g, healthServer
}

func (s *Server) recoveryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			s.log.Error("grpc panic", "method", info.FullMethod, "panic", recovered, "stack", string(debug.Stack()))
			err = status.Error(codes.Internal, "internal error")
		}
	}()
	return handler(ctx, req)
}

func (s *Server) authInterceptor(reflectionEnabled bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		authenticated, err := s.authenticate(ctx, info.FullMethod, reflectionEnabled)
		if err != nil {
			return nil, err
		}
		return handler(authenticated, req)
	}
}

func (s *Server) authStreamInterceptor(reflectionEnabled bool) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		authenticated, err := s.authenticate(stream.Context(), info.FullMethod, reflectionEnabled)
		if err != nil {
			return err
		}
		return handler(srv, &contextServerStream{ServerStream: stream, ctx: authenticated})
	}
}

type contextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *contextServerStream) Context() context.Context { return s.ctx }

func (s *Server) authenticate(ctx context.Context, method string, reflectionEnabled bool) (context.Context, error) {
	policy, classified := parity.RPCPolicies[method]
	if method == grpc_health_v1.Health_Check_FullMethodName || method == grpc_health_v1.Health_Watch_FullMethodName {
		policy, classified = parity.AuthPublic, true
	}
	if reflectionEnabled && (method == reflectionv1.ServerReflection_ServerReflectionInfo_FullMethodName || method == reflectionv1alpha.ServerReflection_ServerReflectionInfo_FullMethodName) {
		policy, classified = parity.AuthPublic, true
	}
	if !classified {
		return nil, grpcError(codes.PermissionDenied, "RPC_DENIED", "rpc is not classified")
	}
	if policy == parity.AuthPublic {
		return ctx, nil
	}
	if policy != parity.AuthHuman {
		return nil, grpcError(codes.PermissionDenied, "RPC_DENIED", "rpc is not classified")
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, grpcError(codes.Unauthenticated, "MISSING_BEARER", "authorization metadata is required")
	}
	values := md.Get("authorization")
	if len(values) != 1 {
		return nil, grpcError(codes.Unauthenticated, "INVALID_BEARER", "exactly one Bearer authorization value is required")
	}
	raw := values[0]
	if !strings.HasPrefix(raw, "Bearer ") {
		return nil, grpcError(codes.Unauthenticated, "INVALID_BEARER", "authorization must use the Bearer scheme")
	}
	token := strings.TrimPrefix(raw, "Bearer ")
	if token == "" || token != strings.TrimSpace(token) || strings.ContainsAny(token, " \t\r\n") {
		return nil, grpcError(codes.Unauthenticated, "INVALID_BEARER", "bearer token is empty or malformed")
	}
	claims, err := s.auth.VerifyAccessToken(ctx, token, jwtutil.TypeAccess)
	if err != nil {
		return nil, mapError(err)
	}
	actor, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, grpcError(codes.Unauthenticated, "INVALID_SUBJECT", "access token subject is invalid")
	}
	return context.WithValue(ctx, actorKey{}, actor), nil
}

func (s *Server) recoveryStreamInterceptor(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			s.log.Error("grpc stream panic", "method", info.FullMethod, "panic", recovered, "stack", string(debug.Stack()))
			err = status.Error(codes.Internal, "internal error")
		}
	}()
	return handler(srv, stream)
}

func actorFromContext(ctx context.Context) (uuid.UUID, error) {
	actor, ok := ctx.Value(actorKey{}).(uuid.UUID)
	if !ok || actor == uuid.Nil {
		return uuid.Nil, grpcError(codes.Unauthenticated, "MISSING_ACTOR", "authenticated actor is missing")
	}
	return actor, nil
}

func errorInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	resp, err := handler(ctx, req)
	if err == nil {
		return resp, nil
	}
	return nil, mapError(err)
}

func errorStreamInterceptor(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return mapError(handler(srv, stream))
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "23505", "23P01":
			return grpcError(codes.AlreadyExists, "ALREADY_EXISTS", "resource already exists")
		case "23503":
			return grpcError(codes.FailedPrecondition, "RELATED_RESOURCE_REQUIRED", "related resource does not exist")
		case "23514", "22P02":
			return grpcError(codes.InvalidArgument, "INVALID_ARGUMENT", "value violates a database constraint")
		case "40001", "40P01":
			return grpcError(codes.Aborted, "TRANSACTION_RETRY", "transaction must be retried")
		}
	}
	switch {
	case errors.Is(err, service.ErrInvalidCredentials), errors.Is(err, service.ErrOTPInvalid), errors.Is(err, service.ErrStaleSigningKey), errors.Is(err, service.ErrWrongTokenType):
		return grpcError(codes.Unauthenticated, "INVALID_CREDENTIAL", "authentication failed")
	case errors.Is(err, service.ErrBanned), errors.Is(err, service.ErrForbidden):
		return grpcError(codes.PermissionDenied, "FORBIDDEN", "operation is forbidden")
	case errors.Is(err, service.ErrLocked):
		return grpcError(codes.FailedPrecondition, "ACCOUNT_LOCKED", "account is locked")
	case errors.Is(err, service.ErrNotFound):
		return grpcError(codes.NotFound, "NOT_FOUND", "resource not found")
	case errors.Is(err, service.ErrTagNotConfigured):
		return grpcError(codes.FailedPrecondition, "TAG_NOT_CONFIGURED", err.Error())
	case errors.Is(err, service.ErrRequestNotPending):
		return grpcError(codes.FailedPrecondition, "REQUEST_NOT_PENDING", err.Error())
	case errors.Is(err, service.ErrInvalidInvite):
		return grpcError(codes.FailedPrecondition, "INVALID_INVITE", "registration invite is invalid or expired")
	case errors.Is(err, service.ErrInvalidArgument), errors.Is(err, service.ErrPasswordPolicy), errors.Is(err, service.ErrCannotBanSelf), errors.Is(err, service.ErrCannotBanSuperuser):
		return grpcError(codes.InvalidArgument, "INVALID_ARGUMENT", err.Error())
	default:
		return grpcError(codes.Internal, "INTERNAL", "internal error")
	}
}

func grpcError(code codes.Code, reason, message string) error {
	st := status.New(code, message)
	withDetails, err := st.WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: errorDomain})
	if err != nil {
		return st.Err()
	}
	return withDetails.Err()
}

func invalid(field, problem string) error {
	return grpcError(codes.InvalidArgument, "INVALID_ARGUMENT", fmt.Sprintf("%s: %s", field, problem))
}
