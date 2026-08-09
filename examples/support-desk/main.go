package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/olegkapshai/auth-master/examples/internal/authz"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	connection, err := grpc.NewClient(env("AUTH_GRPC_ADDR", "localhost:9090"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Close()
	listener, err := net.Listen("tcp", env("GRPC_ADDR", ":8093"))
	if err != nil {
		log.Fatal(err)
	}
	server := grpc.NewServer()
	checker := authz.GRPCChecker{Client: authv1.NewAuthServiceClient(connection)}
	verifier := authz.JWTSubjectVerifier{Verifier: checker}
	store := newTicketStore()
	registerSupportService(server, &supportServer{verifier: verifier, checker: checker, store: store})
	go func() {
		log.Printf("support desk gRPC example listening on %s", listener.Addr())
		if serveErr := server.Serve(listener); serveErr != nil {
			log.Fatal(serveErr)
		}
	}()
	selfConnection, err := grpc.NewClient(env("SUPPORT_SELF_GRPC_ADDR", "localhost:8093"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	defer selfConnection.Close()
	httpServer := &http.Server{Addr: env("HTTP_ADDR", ":8094"), Handler: supportHTTPHandler(selfConnection, store), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("support desk UI listening on %s", httpServer.Addr)
	log.Fatal(httpServer.ListenAndServe())
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
