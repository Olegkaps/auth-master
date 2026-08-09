package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/olegkapshai/auth-master/examples/internal/authz"
	"google.golang.org/grpc"
	grpccredentials "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	grpcAddress := env("AUTH_GRPC_ADDR", "localhost:9090")
	transportCredentials := func() grpccredentials.TransportCredentials {
		serverName := os.Getenv("AUTH_GRPC_TLS_SERVER_NAME")
		if serverName != "" {
			return grpccredentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName})
		}
		return insecure.NewCredentials()
	}()
	connection, err := grpc.NewClient(grpcAddress, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Close()

	minioClient, err := minio.New(env("MINIO_ENDPOINT", "localhost:9000"), &minio.Options{
		Creds: credentials.NewStaticV4(
			requiredEnv("MINIO_ACCESS_KEY"),
			requiredEnv("MINIO_SECRET_KEY"),
			"",
		),
		Secure: strings.EqualFold(os.Getenv("MINIO_SECURE"), "true"),
	})
	if err != nil {
		log.Fatal(err)
	}
	objects := minioStore{client: minioClient, bucket: env("MINIO_BUCKET", "user-folders")}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ensureWithRetry(ctx, objects, 250*time.Millisecond); err != nil {
		log.Fatal(err)
	}

	provisioner := grpcProvisioner{
		auth: authv1.NewAuthServiceClient(connection), admin: authv1.NewAdminServiceClient(connection),
		roles: authv1.NewRoleServiceClient(connection),
	}
	app := storageApp{
		checker:     authz.GRPCChecker{Client: authv1.NewAuthServiceClient(connection)},
		provisioner: provisioner, objects: objects,
		service: serviceCredentials{login: requiredEnv("AUTH_SERVICE_LOGIN"), secret: requiredEnv("AUTH_SERVICE_SECRET")},
		pending: newPendingRegistrations(), maxUploadBytes: 16 << 20,
	}
	server := &http.Server{Addr: env("HTTP_ADDR", ":8091"), Handler: app.routes(), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("MinIO storage example listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func ensureWithRetry(ctx context.Context, store objectStore, delay time.Duration) error {
	var lastErr error
	for {
		if err := store.Ensure(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("wait for object store: %w: %v", ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func requiredEnv(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}
