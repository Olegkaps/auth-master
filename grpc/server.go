// grpc/server.go

package grpc

import (
	"log"
	"net"

	"github.com/Olegkaps/auth-master/config"
	pb "github.com/Olegkaps/auth-master/proto" // generated protobuf
	"github.com/Olegkaps/auth-master/services"
	"google.golang.org/grpc"
)

type Server struct {
	authService  *services.AuthService
	roleService  *services.RoleService
	tokenService *services.TokenService
}

func NewServer(auth *services.AuthService, role *services.RoleService, token *services.TokenService) *Server {
	return &Server{
		authService:  auth,
		roleService:  role,
		tokenService: token,
	}
}

func (s *Server) Start(cfg config.Config) error {
	lis, err := net.Listen("tcp", ":"+cfg.GRPCPort)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()

	pb.RegisterAuthServiceServer(grpcServer, s.authService)
	pb.RegisterRoleServiceServer(grpcServer, s.roleService)
	pb.RegisterTokenServiceServer(grpcServer, s.tokenService)

	log.Printf("gRPC server starting on :%s", cfg.GRPCPort)
	return grpcServer.Serve(lis)
}
