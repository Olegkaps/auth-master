package grpctransport

import (
	"context"
	"strings"
	"time"

	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/olegkapshai/auth-master/internal/service"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) GetMe(ctx context.Context, _ *authv1.GetMeRequest) (*authv1.GetMeResponse, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	user, err := s.auth.CurrentUser(ctx, actor)
	if err != nil {
		return nil, err
	}
	return &authv1.GetMeResponse{User: pbUser(*user)}, nil
}

func (s *Server) CheckMyRole(ctx context.Context, req *authv1.CheckMyRoleRequest) (*authv1.HasRoleResponse, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	role, err := normalizeText("role_name", req.GetRoleName(), 100)
	if err != nil {
		return nil, err
	}
	has, err := s.auth.UserHasRoleName(ctx, actor, role)
	return &authv1.HasRoleResponse{HasRole: has}, err
}

func (s *Server) CheckMyRoleWithTag(ctx context.Context, req *authv1.CheckMyRoleWithTagRequest) (*authv1.HasRoleWithTagResponse, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	role, err := normalizeText("role_name", req.GetRoleName(), 100)
	if err != nil {
		return nil, err
	}
	tags, err := normalizeTags([]string{req.GetTag()})
	if err != nil {
		return nil, err
	}
	has, err := s.auth.UserHasRoleWithTag(ctx, actor, role, tags[0])
	return &authv1.HasRoleWithTagResponse{HasRoleWithTag: has}, err
}

func (s *Server) ListMyRoleAccess(ctx context.Context, _ *authv1.ListMyRoleAccessRequest) (*authv1.ListMyRoleAccessResponse, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	access, err := s.auth.EffectiveRoleAccess(ctx, actor)
	if err != nil {
		return nil, err
	}
	out := make([]*authv1.EffectiveRoleAccess, 0, len(access))
	for _, item := range access {
		out = append(out, &authv1.EffectiveRoleAccess{RoleId: item.RoleID.String(), CanManage: item.CanManage})
	}
	return &authv1.ListMyRoleAccessResponse{Roles: out}, nil
}

func (s *Server) StartPasswordChangeOTP(ctx context.Context, _ *authv1.StartPasswordChangeOTPRequest) (*emptypb.Empty, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.auth.StartPasswordChange2FA(ctx, actor); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) ChangePassword(ctx context.Context, req *authv1.ChangePasswordRequest) (*emptypb.Empty, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.auth.ChangePassword(ctx, actor, req.GetOldPassword(), req.GetNewPassword(), req.GetCode()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) StartStepUp2FA(ctx context.Context, req *authv1.StartStepUp2FARequest) (*authv1.StartStepUp2FAResponse, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var ttl time.Duration
	if req.GetTtl() != nil {
		if err := req.GetTtl().CheckValid(); err != nil {
			return nil, invalid("ttl", "invalid duration")
		}
		ttl, err = service.DurationFromParts(req.GetTtl().GetSeconds(), req.GetTtl().GetNanos())
		if err != nil {
			return nil, err
		}
	}
	correlation, err := s.auth.BeginStepUp2FA(ctx, actor, ttl)
	if err != nil {
		return nil, err
	}
	return &authv1.StartStepUp2FAResponse{CorrelationId: correlation}, nil
}

func (s *Server) GetStepUp2FAStatus(ctx context.Context, req *authv1.GetStepUp2FAStatusRequest) (*authv1.GetStepUp2FAStatusResponse, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.GetCorrelationId()) == "" {
		return nil, invalid("correlation_id", "is required")
	}
	value, err := s.auth.StepUp2FAStatusForUser(ctx, req.GetCorrelationId(), actor)
	if err != nil {
		return nil, err
	}
	return &authv1.GetStepUp2FAStatusResponse{Status: value}, nil
}

func (s *Server) ExpireStepUp2FA(ctx context.Context, req *authv1.ExpireStepUp2FARequest) (*emptypb.Empty, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.auth.ExpireStepUp2FASessionForUser(ctx, req.GetCorrelationId(), actor); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) ListSessions(ctx context.Context, _ *authv1.ListSessionsRequest) (*authv1.ListSessionsResponse, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	sessions, err := s.auth.Sessions(ctx, actor)
	if err != nil {
		return nil, err
	}
	out := make([]*authv1.RefreshSession, 0, len(sessions))
	for _, session := range sessions {
		row := &authv1.RefreshSession{Id: session.ID.String(), DeviceId: session.DeviceID, CreatedAt: pbTimestamp(session.CreatedAt), ExpiresAt: pbTimestamp(session.ExpiresAt), Revoked: session.RevokedAt != nil}
		if session.DeviceLabel != nil {
			row.DeviceLabel = session.DeviceLabel
		}
		out = append(out, row)
	}
	return &authv1.ListSessionsResponse{Sessions: out}, nil
}

func (s *Server) RevokeOwnSession(ctx context.Context, req *authv1.RevokeOwnSessionRequest) (*emptypb.Empty, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	session, err := parseID("session_id", req.GetSessionId())
	if err != nil {
		return nil, err
	}
	if err := s.auth.RevokeOwnSession(ctx, actor, session); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) StartSessionRevokeOTP(ctx context.Context, _ *authv1.StartSessionRevokeOTPRequest) (*emptypb.Empty, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.auth.StartSessionRevokeOTP(ctx, actor); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) RevokeSessionWithOTP(ctx context.Context, req *authv1.RevokeSessionWithOTPRequest) (*emptypb.Empty, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	session, err := parseID("session_id", req.GetSessionId())
	if err != nil {
		return nil, err
	}
	if err := s.auth.RevokeSessionWithOTP(ctx, actor, session, req.GetCode()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) CreateRegistrationInvite(ctx context.Context, req *authv1.CreateRegistrationInviteRequest) (*authv1.CreateRegistrationInviteResponse, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	var email *string
	if req.Email != nil {
		value := strings.TrimSpace(req.GetEmail())
		if value == "" {
			return nil, invalid("email", "must not be empty when present")
		}
		email = &value
	}
	var ttl time.Duration
	if req.GetTtl() != nil {
		if err := req.GetTtl().CheckValid(); err != nil {
			return nil, invalid("ttl", "invalid duration")
		}
		ttl, err = service.DurationFromParts(req.GetTtl().GetSeconds(), req.GetTtl().GetNanos())
		if err != nil {
			return nil, err
		}
	}
	token, expiresAt, url, err := s.auth.CreateRegistrationInvite(ctx, actor, email, req.GetSuperuser(), ttl)
	if err != nil {
		return nil, err
	}
	return &authv1.CreateRegistrationInviteResponse{Token: token, ExpiresAt: pbTimestamp(expiresAt), RegistrationUrl: url}, nil
}

func (s *Server) RotateSigningKey(ctx context.Context, _ *authv1.RotateSigningKeyRequest) (*emptypb.Empty, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.auth.RotateSigningKeyForActor(ctx, actor); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) ListUsers(ctx context.Context, req *authv1.ListUsersRequest) (*authv1.ListUsersResponse, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	query, cursor, size, err := page(req.GetPage())
	if err != nil {
		return nil, err
	}
	users, next, total, err := s.auth.UsersPage(ctx, actor, query, cursor, size)
	if err != nil {
		return nil, err
	}
	out := make([]*authv1.User, 0, len(users))
	for _, user := range users {
		out = append(out, pbUser(user))
	}
	response := &authv1.ListUsersResponse{Users: out, PageSize: int32(size), NextCursor: encodeCursor(next)}
	if total != nil {
		response.Total = total
	}
	return response, nil
}

func (s *Server) BanUser(ctx context.Context, req *authv1.BanUserRequest) (*emptypb.Empty, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	target, err := parseID("user_id", req.GetUserId())
	if err != nil {
		return nil, err
	}
	if err := s.auth.BanUser(ctx, actor, target, req.GetReason()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) UnbanUser(ctx context.Context, req *authv1.UnbanUserRequest) (*emptypb.Empty, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	target, err := parseID("user_id", req.GetUserId())
	if err != nil {
		return nil, err
	}
	if err := s.auth.UnbanUser(ctx, actor, target); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
