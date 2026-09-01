package grpctransport

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/olegkapshai/auth-master/internal/config"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/olegkapshai/auth-master/internal/service"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type blockedGRPCPublicMailRepo struct {
	repository.Repository
	started chan struct{}
	release chan struct{}
}

func TestPublicMailGRPCAdaptersShareServiceIdentityBound(t *testing.T) {
	key := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	cfg := &config.Config{SigningKeyMasterKey: key, PasswordHistoryEncryptionKey: key, PublicMailWorkers: 1, PublicMailQueueSize: 1, PublicMailJobTimeout: time.Second}
	auth, err := service.NewAuth(cfg, &blockedGRPCPublicMailRepo{}, noOpGRPCMailer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	server := &Server{auth: auth, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	oversized := strings.Repeat("x", service.MaxPublicIdentityBytes+1)

	_, err = server.StartMagicLink(context.Background(), &authv1.StartMagicLinkRequest{Login: oversized})
	require.ErrorIs(t, err, service.ErrInvalidArgument)
	require.Equal(t, codes.InvalidArgument, status.Code(mapError(err)))
	_, err = server.StartPasswordReset(context.Background(), &authv1.StartPasswordResetRequest{Login: oversized})
	require.ErrorIs(t, err, service.ErrInvalidArgument)
	require.Equal(t, codes.InvalidArgument, status.Code(mapError(err)))
	require.NoError(t, auth.Shutdown(context.Background()))
}

func (r *blockedGRPCPublicMailRepo) GetHumanUserByLoginOrEmail(ctx context.Context, _ string) (*domain.User, error) {
	close(r.started)
	select {
	case <-r.release:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type noOpGRPCMailer struct{}

func (noOpGRPCMailer) Send(context.Context, []string, string, string) error { return nil }

func TestPublicMailGRPCAdaptersReturnWhilePrivateLookupIsBlocked(t *testing.T) {
	for _, test := range []struct {
		name string
		call func(*Server) error
	}{
		{"magic link", func(s *Server) error {
			_, err := s.StartMagicLink(context.Background(), &authv1.StartMagicLinkRequest{Login: "blocked@example.test"})
			return err
		}},
		{"password reset", func(s *Server) error {
			_, err := s.StartPasswordReset(context.Background(), &authv1.StartPasswordResetRequest{Login: "blocked@example.test"})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
			cfg := &config.Config{SigningKeyMasterKey: key, PasswordHistoryEncryptionKey: key, PublicMailWorkers: 1, PublicMailQueueSize: 1, PublicMailJobTimeout: time.Second}
			repo := &blockedGRPCPublicMailRepo{started: make(chan struct{}), release: make(chan struct{})}
			auth, err := service.NewAuth(cfg, repo, noOpGRPCMailer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			require.NoError(t, err)
			server := &Server{auth: auth, repo: repo, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			returned := make(chan error, 1)
			go func() { returned <- test.call(server) }()
			<-repo.started
			select {
			case err := <-returned:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("gRPC adapter waited for private identity lookup")
			}
			close(repo.release)
			require.NoError(t, auth.Shutdown(context.Background()))
		})
	}
}
