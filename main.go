// main.go

package main

import (
	"context"
	"log"
	"time"

	"github.com/Olegkaps/auth-master/config"
	"github.com/Olegkaps/auth-master/db"
	"github.com/Olegkaps/auth-master/grpc"
	"github.com/Olegkaps/auth-master/http"
	"github.com/Olegkaps/auth-master/logging"
	"github.com/Olegkaps/auth-master/metrics"
	"github.com/Olegkaps/auth-master/services"
)

func main() {
	cfg := config.LoadConfig()

	err := logging.InitLogging(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize logging: %v", err)
	}

	metrics.RegisterMetrics()

	err = db.InitDB()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	db.InitRedis()

	// grpc
	authService := services.NewAuthService(db.DB)
	roleService := services.NewRoleService(db.DB)
	tokenService := services.NewTokenService(db.DB)

	grpcServer := grpc.NewServer(authService, roleService, tokenService)
	go func() {
		err := grpcServer.Start(cfg)
		if err != nil {
			log.Fatalf("gRPC server failed: %v", err)
		}
	}()

	//background
	cleanupService := services.NewCleanupService(
		db.DB,
		5*time.Minute,
		100,
	)

	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	go cleanupService.Start(cleanupCtx)

	// http
	err = http.StartHTTPServer(cfg)
	if err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}

	cleanupCancel() // TODO: change
}
