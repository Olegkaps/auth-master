package grpctransport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func TestReflectionEnabledAndHealthStartsNotServing(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, _ := New(nil, nil, logger, Options{Reflection: true})
	defer server.Stop()
	_, foundV1 := server.GetServiceInfo()["grpc.reflection.v1.ServerReflection"]
	require.True(t, foundV1)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	response, err := grpc_health_v1.NewHealthClient(conn).Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, response.GetStatus())
	server.Stop()
	<-serveDone
}

func TestReceiveSizeLimitRejectsBeforeHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, _ := New(nil, nil, logger, Options{MaxReceiveSize: 64})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	defer func() { server.Stop(); <-serveDone }()
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	_, err = authv1.NewAuthServiceClient(conn).PreviewRegistrationInvite(context.Background(), &authv1.PreviewRegistrationInviteRequest{Token: string(make([]byte, 1024))})
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestSendSizeLimitRejectsResponseOverTCP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, healthServer := New(nil, nil, logger, Options{MaxSendSize: 1})
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	defer func() { server.Stop(); <-serveDone }()
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	_, err = grpc_health_v1.NewHealthClient(conn).Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestHealthWatchObservesShutdownTransition(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, healthServer := New(nil, nil, logger, Options{})
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	defer func() { server.Stop(); <-serveDone }()
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	watch, err := grpc_health_v1.NewHealthClient(conn).Watch(ctx, &grpc_health_v1.HealthCheckRequest{})
	require.NoError(t, err)
	statusUpdate, err := watch.Recv()
	require.NoError(t, err)
	require.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, statusUpdate.GetStatus())

	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	statusUpdate, err = watch.Recv()
	require.NoError(t, err)
	require.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, statusUpdate.GetStatus())
}

func TestTLSHandshakeAndPlaintextRejection(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, healthServer := New(nil, nil, logger, Options{Credentials: credentials.NewTLS(serverTLS)})
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	defer func() { server.Stop(); <-serveDone }()

	tlsConn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	require.NoError(t, err)
	response, err := grpc_health_v1.NewHealthClient(tlsConn).Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, response.GetStatus())
	require.NoError(t, tlsConn.Close())

	plainConn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer plainConn.Close()
	callCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = grpc_health_v1.NewHealthClient(plainConn).Check(callCtx, &grpc_health_v1.HealthCheckRequest{})
	require.Equal(t, codes.Unavailable, status.Code(err))
}

func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots.AddCert(parsed)
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}},
		&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "localhost"}
}
