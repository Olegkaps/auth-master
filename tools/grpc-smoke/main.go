// Command grpc-smoke checks the standard gRPC health endpoint of a running authd.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	address := os.Getenv("GRPC_SMOKE_ADDR")
	if address == "" {
		address = "localhost:9090"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	response, err := grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		panic(err)
	}
	if response.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		panic(fmt.Sprintf("gRPC health at %s is %s", address, response.GetStatus()))
	}
	fmt.Printf("gRPC health at %s: SERVING\n", address)
}
