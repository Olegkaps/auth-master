package grpctransport

import (
	"context"
	"net"
	"strings"

	"github.com/google/uuid"
	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/olegkapshai/auth-master/internal/jwtutil"
	"github.com/olegkapshai/auth-master/internal/service"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) PreviewRegistrationInvite(ctx context.Context, req *authv1.PreviewRegistrationInviteRequest) (*authv1.PreviewRegistrationInviteResponse, error) {
	preview, err := s.auth.PreviewRegistrationInvite(ctx, strings.TrimSpace(req.GetToken()))
	if err != nil {
		return nil, err
	}
	out := &authv1.PreviewRegistrationInviteResponse{Valid: preview.Valid}
	if preview.Valid {
		if preview.Email != nil {
			out.Email = preview.Email
		}
		out.Superuser = preview.Superuser
		out.ExpiresAt = pbTimestamp(preview.ExpiresAt)
	}
	return out, nil
}

func (s *Server) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	if strings.TrimSpace(req.GetInviteToken()) == "" {
		return nil, invalid("invite_token", "is required")
	}
	id, err := s.auth.Register(ctx, req.GetInviteToken(), req.GetLogin(), req.GetEmail(), req.GetPassword())
	if err != nil {
		return nil, err
	}
	return &authv1.RegisterResponse{UserId: id.String()}, nil
}

func (s *Server) LoginPassword(ctx context.Context, req *authv1.LoginPasswordRequest) (*authv1.LoginPasswordResponse, error) {
	var ip net.IP
	if value := strings.TrimSpace(req.GetClientIp()); value != "" {
		ip = net.ParseIP(value)
		if ip == nil {
			return nil, invalid("client_ip", "must be an IP address")
		}
	}
	result, err := s.auth.LoginPassword(ctx, req.GetLogin(), req.GetPassword(), ip)
	if err != nil {
		return nil, err
	}
	return &authv1.LoginPasswordResponse{OtpSent: result.OTPRequired, LoginChallenge: result.LoginChallenge, PasswordExpired: result.PasswordExpired}, nil
}

func (s *Server) IssueServiceToken(ctx context.Context, req *authv1.IssueServiceTokenRequest) (*authv1.IssueServiceTokenResponse, error) {
	token, expiresAt, err := s.auth.IssueServiceToken(ctx, req.GetLogin(), req.GetSecret())
	if err != nil {
		return nil, err
	}
	return &authv1.IssueServiceTokenResponse{AccessToken: token, ExpiresAt: pbTimestamp(expiresAt)}, nil
}

func tokenSubject(ctx context.Context, auth *service.Auth, token string) (uuid.UUID, error) {
	claims, err := auth.VerifyAccessToken(ctx, strings.TrimSpace(token), jwtutil.TypeAccess)
	if err != nil {
		return uuid.Nil, err
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, grpcError(16, "INVALID_SUBJECT", "access token subject is invalid")
	}
	return id, nil
}

func (s *Server) CheckTokenRole(ctx context.Context, req *authv1.CheckTokenRoleRequest) (*authv1.HasRoleResponse, error) {
	role, err := normalizeText("role_name", req.GetRoleName(), 100)
	if err != nil {
		return nil, err
	}
	uid, err := tokenSubject(ctx, s.auth, req.GetAccessToken())
	if err != nil {
		return nil, err
	}
	has, err := s.auth.UserHasRoleName(ctx, uid, role)
	return &authv1.HasRoleResponse{HasRole: has}, err
}

func (s *Server) CheckTokenRoleWithTag(ctx context.Context, req *authv1.CheckTokenRoleWithTagRequest) (*authv1.HasRoleWithTagResponse, error) {
	role, err := normalizeText("role_name", req.GetRoleName(), 100)
	if err != nil {
		return nil, err
	}
	tags, err := normalizeTags([]string{req.GetTag()})
	if err != nil {
		return nil, err
	}
	uid, err := tokenSubject(ctx, s.auth, req.GetAccessToken())
	if err != nil {
		return nil, err
	}
	has, err := s.auth.UserHasRoleWithTag(ctx, uid, role, tags[0])
	return &authv1.HasRoleWithTagResponse{HasRoleWithTag: has}, err
}

func claimsResponse(claims *jwtutil.Claims) *authv1.TokenClaims {
	return &authv1.TokenClaims{Subject: claims.Subject, Login: claims.Login, KeyId: claims.Kid, TokenType: claims.Typ}
}

func (s *Server) InspectToken(ctx context.Context, req *authv1.InspectTokenRequest) (*authv1.InspectTokenResponse, error) {
	claims, err := s.auth.VerifyAccessOrServiceToken(ctx, strings.TrimSpace(req.GetToken()))
	if err != nil {
		return nil, err
	}
	return &authv1.InspectTokenResponse{Claims: claimsResponse(claims)}, nil
}

func (s *Server) VerifyAccessToken(ctx context.Context, req *authv1.VerifyAccessTokenRequest) (*authv1.VerifyAccessTokenResponse, error) {
	claims, err := s.auth.VerifyAccessToken(ctx, strings.TrimSpace(req.GetAccessToken()), jwtutil.TypeAccess)
	if err != nil {
		return nil, err
	}
	return &authv1.VerifyAccessTokenResponse{Claims: claimsResponse(claims)}, nil
}

func tokenPair(pair *service.TokenPair) *authv1.TokenPair {
	return &authv1.TokenPair{AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken, ExpiresAt: pbTimestamp(pair.ExpiresAt)}
}

func (s *Server) VerifyLoginOTP(ctx context.Context, req *authv1.VerifyLoginOTPRequest) (*authv1.VerifyLoginOTPResponse, error) {
	if strings.TrimSpace(req.GetChallenge()) == "" {
		return nil, invalid("challenge", "is required")
	}
	if strings.TrimSpace(req.GetDeviceId()) == "" {
		return nil, invalid("device_id", "is required")
	}
	pair, _, err := s.auth.LoginVerifyOTP(ctx, req.GetChallenge(), req.GetCode(), req.GetDeviceId(), req.GetDeviceLabel())
	if err != nil {
		return nil, err
	}
	return &authv1.VerifyLoginOTPResponse{Tokens: tokenPair(pair)}, nil
}

func (s *Server) StartMagicLink(ctx context.Context, req *authv1.StartMagicLinkRequest) (*emptypb.Empty, error) {
	if _, err := normalizeText("login", req.GetLogin(), 100); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, s.auth.StartMagicLink(ctx, req.GetLogin())
}

func (s *Server) CompleteMagicLink(ctx context.Context, req *authv1.CompleteMagicLinkRequest) (*authv1.CompleteMagicLinkResponse, error) {
	if strings.TrimSpace(req.GetDeviceId()) == "" {
		return nil, invalid("device_id", "is required")
	}
	pair, _, err := s.auth.CompleteMagicLink(ctx, req.GetToken(), req.GetDeviceId(), req.GetDeviceLabel())
	if err != nil {
		return nil, err
	}
	return &authv1.CompleteMagicLinkResponse{Tokens: tokenPair(pair)}, nil
}

func (s *Server) StartPasswordReset(ctx context.Context, req *authv1.StartPasswordResetRequest) (*emptypb.Empty, error) {
	if _, err := normalizeText("login", req.GetLogin(), 100); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, s.auth.StartPasswordReset(ctx, req.GetLogin())
}

func (s *Server) CompletePasswordReset(ctx context.Context, req *authv1.CompletePasswordResetRequest) (*emptypb.Empty, error) {
	if err := s.auth.ResetPasswordWithOTP(ctx, req.GetLogin(), req.GetCode(), req.GetNewPassword()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) Refresh(ctx context.Context, req *authv1.RefreshRequest) (*authv1.RefreshResponse, error) {
	if strings.TrimSpace(req.GetRefreshToken()) == "" {
		return nil, invalid("refresh_token", "is required")
	}
	pair, err := s.auth.Refresh(ctx, req.GetRefreshToken(), req.GetDeviceId(), req.GetDeviceLabel())
	if err != nil {
		return nil, err
	}
	return &authv1.RefreshResponse{Tokens: tokenPair(pair)}, nil
}

func (s *Server) Logout(ctx context.Context, req *authv1.LogoutRequest) (*emptypb.Empty, error) {
	if strings.TrimSpace(req.GetRefreshToken()) == "" {
		return nil, invalid("refresh_token", "is required")
	}
	if err := s.auth.Logout(ctx, req.GetRefreshToken()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) CompleteStepUp2FA(ctx context.Context, req *authv1.CompleteStepUp2FARequest) (*emptypb.Empty, error) {
	if err := s.auth.CompleteStepUp2FAOTP(ctx, req.GetCorrelationId(), req.GetCode()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
