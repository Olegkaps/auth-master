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
	"log/slog"
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
	httptransport "github.com/olegkapshai/auth-master/internal/transport/http"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	log := newLogger(cfg.LogLevel)
	ctx := context.Background()

	db, err := migrate.Open(cfg.DatabaseURL)
	if err != nil {
		log.Error("db connect", "err", err)
		os.Exit(1)
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Error("db sql", "err", err)
		os.Exit(1)
	}
	defer sqlDB.Close()
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetConnMaxLifetime(time.Hour)

	if err := migrate.Up(db); err != nil {
		log.Error("migrate", "err", err)
		os.Exit(1)
	}

	repo := repository.New(db)
	m := &mail.Sender{
		Host: cfg.SMTPHost, Port: cfg.SMTPPort,
		User: cfg.SMTPUser, Password: cfg.SMTPPassword,
		From: cfg.MailFrom,
	}
	authSvc, err := service.NewAuth(&cfg, repo, m, log)
	if err != nil {
		log.Error("auth service", "err", err)
		os.Exit(1)
	}
	if err := authSvc.EnsureBootstrap(ctx); err != nil {
		log.Error("signing bootstrap", "err", err)
		os.Exit(1)
	}
	if err := authSvc.EnsureBootstrapAdmin(ctx); err != nil {
		log.Error("bootstrap admin", "err", err)
		os.Exit(1)
	}

	if cfg.SigningKeyRotateEvery > 0 {
		go func() {
			t := time.NewTicker(cfg.SigningKeyRotateEvery)
			defer t.Stop()
			for range t.C {
				if err := authSvc.RotateSigningKey(context.Background()); err != nil {
					log.Error("signing key rotate", "err", err)
				}
			}
		}()
	}

	hs := httptransport.NewServer(&cfg, authSvc, repo, log)
	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: hs.Handler()}

	go func() {
		log.Info("http listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("http serve", "err", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	shctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shctx)
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
