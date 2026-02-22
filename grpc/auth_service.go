// grpc/auth_service.go

// DO WE NEED THIS FILE ?

package grpc

import (
	"context"

	pb "github.com/Olegkaps/auth-master/proto" // generated protobuf
)

func (s *Server) ValidateAccessToken(ctx context.Context, req *pb.ValidateAccessTokenRequest) (*pb.ValidateAccessTokenResponse, error) {
	token, err := jwt.ValidateToken(req.Token)
	if err != nil || !token.Valid {
		return &pb.ValidateAccessTokenResponse{IsValid: false}, nil
	}

	claims := token.Claims.(jwt.MapClaims)
	return &pb.ValidateAccessTokenResponse{
		IsValid: true,
		Claims:  claims,
	}, nil
}

func (s *Server) IssueServiceToken(ctx context.Context, req *pb.IssueServiceTokenRequest) (*pb.IssueServiceTokenResponse, error) {
	// Логика выдачи токена для сервиса (проверка сертификата/секрета)
	token, err := generateServiceToken(req.ServiceId)
	if err != nil {
		return nil, err
	}
	return &pb.IssueServiceTokenResponse{Token: token}, nil
}
