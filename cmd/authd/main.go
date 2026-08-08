// @title                   Auth service API
// @version                 1.0
// @description             Authentication and authorization REST API (JWT access + refresh, OTP, RBAC, registration invites).
// @host                    localhost:8080
// @BasePath                /
// @schemes                 http https
//
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description             Type "Bearer" followed by a space and the access JWT.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/olegkapshai/auth-master/internal/config"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/olegkapshai/auth-master/internal/migrate"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/olegkapshai/auth-master/internal/service"
	grpctransport "github.com/olegkapshai/auth-master/internal/transport/grpc"
	httptransport "github.com/olegkapshai/auth-master/internal/transport/http"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	log := newLogger(cfg.LogLevel)
	if err := run(cfg, log); err != nil {
		log.Error("authd stopped", "err", err)
		os.Exit(1)
	}
}

func run(cfg config.Config, log *slog.Logger) error {
	ctx := context.Background()

	db, err := migrate.Open(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("db connect: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("db sql: %w", err)
	}
	defer sqlDB.Close()
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetConnMaxLifetime(time.Hour)

	if err := migrate.Up(db); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	repo := repository.New(db)
	m := &mail.Sender{
		Host: cfg.SMTPHost, Port: cfg.SMTPPort,
		User: cfg.SMTPUser, Password: cfg.SMTPPassword,
		From: cfg.MailFrom,
	}
	authSvc, err := service.NewAuth(&cfg, repo, m, log)
	if err != nil {
		return fmt.Errorf("auth service: %w", err)
	}
	if err := authSvc.EnsureBootstrap(ctx); err != nil {
		return fmt.Errorf("signing bootstrap: %w", err)
	}
	if err := authSvc.EnsureBootstrapAdmin(ctx); err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}

	rotateCtx, stopRotation := context.WithCancel(context.Background())
	defer stopRotation()
	if cfg.SigningKeyRotateEvery > 0 {
		go func() {
			t := time.NewTicker(cfg.SigningKeyRotateEvery)
			defer t.Stop()
			for {
				select {
				case <-rotateCtx.Done():
					return
				case <-t.C:
					if err := authSvc.RotateSigningKey(rotateCtx); err != nil && !errors.Is(err, context.Canceled) {
						log.Error("signing key rotate", "err", err)
					}
				}
			}
		}()
	}

	hs := httptransport.NewServer(&cfg, authSvc, repo, log)
	httpServer := &http.Server{Addr: cfg.HTTPAddr, Handler: hs.Handler(), ReadHeaderTimeout: 10 * time.Second}

	transportCredentials, err := loadGRPCCredentials(cfg)
	if err != nil {
		return err
	}
	grpcServer, healthServer := grpctransport.New(authSvc, repo, log, grpctransport.Options{
		Reflection: cfg.GRPCReflection, MaxReceiveSize: cfg.GRPCMaxReceiveBytes,
		MaxSendSize: cfg.GRPCMaxSendBytes, Credentials: transportCredentials,
	})

	httpListener, grpcListener, err := bindListeners(cfg.HTTPAddr, cfg.GRPCAddr)
	if err != nil {
		return err
	}
	defer httpListener.Close()
	defer grpcListener.Close()

	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	serveErrors := make(chan error, 2)

	go func() {
		log.Info("http listening", "addr", httpListener.Addr().String())
		if err := httpServer.Serve(httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrors <- fmt.Errorf("HTTP serve: %w", err)
		}
	}()
	go func() {
		log.Info("grpc listening", "addr", grpcListener.Addr().String(), "tls", transportCredentials != nil, "reflection", cfg.GRPCReflection)
		if err := grpcServer.Serve(grpcListener); err != nil {
			serveErrors <- fmt.Errorf("gRPC serve: %w", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	var serveErr error
	select {
	case <-sig:
	case serveErr = <-serveErrors:
	}

	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	stopRotation()
	shctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	httpDone := make(chan error, 1)
	go func() { httpDone <- httpServer.Shutdown(shctx) }()
	grpcDone := make(chan struct{})
	go func() { grpcServer.GracefulStop(); close(grpcDone) }()
	select {
	case <-grpcDone:
	case <-shctx.Done():
		grpcServer.Stop()
	}
	if err := <-httpDone; err != nil && !errors.Is(err, context.Canceled) && serveErr == nil {
		serveErr = err
	}
	return serveErr
}

func loadGRPCCredentials(cfg config.Config) (credentials.TransportCredentials, error) {
	if cfg.GRPCTLSCertFile == "" {
		return nil, nil
	}
	transportCredentials, err := credentials.NewServerTLSFromFile(cfg.GRPCTLSCertFile, cfg.GRPCTLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load gRPC TLS certificate: %w", err)
	}
	return transportCredentials, nil
}

func bindListeners(httpAddr, grpcAddr string) (net.Listener, net.Listener, error) {
	httpListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("bind HTTP %s: %w", httpAddr, err)
	}
	grpcListener, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		_ = httpListener.Close()
		return nil, nil, fmt.Errorf("bind gRPC %s: %w", grpcAddr, err)
	}
	return httpListener, grpcListener, nil
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv})
	return slog.New(h)
}
