package grpctransport

import (
	"context"
	"strings"

	"github.com/google/uuid"
	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/repository"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) ListRoles(ctx context.Context, req *authv1.ListRolesRequest) (*authv1.ListRolesResponse, error) {
	query, cursor, size, err := page(req.GetPage())
	if err != nil {
		return nil, err
	}
	roles, next, total, err := s.auth.RolesPage(ctx, query, cursor, size)
	if err != nil {
		return nil, err
	}
	out := make([]*authv1.Role, 0, len(roles))
	for _, role := range roles {
		out = append(out, pbRole(role))
	}
	response := &authv1.ListRolesResponse{Roles: out, PageSize: int32(size), NextCursor: encodeCursor(next)}
	if total != nil {
		response.Total = total
	}
	return response, nil
}

func (s *Server) CreateRole(ctx context.Context, req *authv1.CreateRoleRequest) (*authv1.CreateRoleResponse, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	name, err := normalizeText("name", req.GetName(), 100)
	if err != nil {
		return nil, err
	}
	parents := make([]uuid.UUID, 0, len(req.GetParentIds()))
	seen := map[uuid.UUID]bool{}
	for _, raw := range req.GetParentIds() {
		id, parseErr := parseID("parent_ids", raw)
		if parseErr != nil {
			return nil, parseErr
		}
		if !seen[id] {
			seen[id] = true
			parents = append(parents, id)
		}
	}
	id, err := s.auth.CreateRole(ctx, actor, name, req.GetDescription(), parents)
	if err != nil {
		return nil, err
	}
	return &authv1.CreateRoleResponse{RoleId: id.String()}, nil
}

func (s *Server) DeleteRole(ctx context.Context, req *authv1.DeleteRoleRequest) (*emptypb.Empty, error) {
	actor, role, err := actorAndRole(ctx, req.GetRoleId())
	if err != nil {
		return nil, err
	}
	if err := s.auth.DeleteRole(ctx, actor, role); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) UpdateRoleDescription(ctx context.Context, req *authv1.UpdateRoleDescriptionRequest) (*emptypb.Empty, error) {
	actor, role, err := actorAndRole(ctx, req.GetRoleId())
	if err != nil {
		return nil, err
	}
	if err := s.auth.UpdateRoleDescription(ctx, actor, role, req.GetDescription()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) SetRoleParent(ctx context.Context, req *authv1.SetRoleParentRequest) (*emptypb.Empty, error) {
	actor, role, err := actorAndRole(ctx, req.GetRoleId())
	if err != nil {
		return nil, err
	}
	var parent *uuid.UUID
	if req.ParentId != nil {
		value, parseErr := parseID("parent_id", req.GetParentId())
		if parseErr != nil {
			return nil, parseErr
		}
		parent = &value
	}
	if err := s.auth.SetRoleParent(ctx, actor, role, parent); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) MountRole(ctx context.Context, req *authv1.MountRoleRequest) (*emptypb.Empty, error) {
	actor, role, err := actorAndRole(ctx, req.GetRoleId())
	if err != nil {
		return nil, err
	}
	parent, err := parseID("parent_id", req.GetParentId())
	if err != nil {
		return nil, err
	}
	if err := s.auth.Mount(ctx, actor, role, parent); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) UnmountRole(ctx context.Context, req *authv1.UnmountRoleRequest) (*emptypb.Empty, error) {
	actor, role, err := actorAndRole(ctx, req.GetRoleId())
	if err != nil {
		return nil, err
	}
	parent, err := parseID("parent_id", req.GetParentId())
	if err != nil {
		return nil, err
	}
	if err := s.auth.Unmount(ctx, actor, role, parent); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) ListSubgroups(ctx context.Context, req *authv1.ListSubgroupsRequest) (*authv1.ListSubgroupsResponse, error) {
	role, err := parseID("role_id", req.GetRoleId())
	if err != nil {
		return nil, err
	}
	roles, err := s.auth.Subgroups(ctx, role, req.GetRecursive())
	if err != nil {
		return nil, err
	}
	out := make([]*authv1.Role, 0, len(roles))
	for _, item := range roles {
		out = append(out, pbRole(item))
	}
	return &authv1.ListSubgroupsResponse{Roles: out}, nil
}

func (s *Server) AddRoleTag(ctx context.Context, req *authv1.AddRoleTagRequest) (*emptypb.Empty, error) {
	return s.changeRoleTag(ctx, req.GetRoleId(), req.GetTag(), true)
}

func (s *Server) DeleteRoleTag(ctx context.Context, req *authv1.DeleteRoleTagRequest) (*emptypb.Empty, error) {
	return s.changeRoleTag(ctx, req.GetRoleId(), req.GetTag(), false)
}

func (s *Server) changeRoleTag(ctx context.Context, roleRaw, tagRaw string, add bool) (*emptypb.Empty, error) {
	actor, role, err := actorAndRole(ctx, roleRaw)
	if err != nil {
		return nil, err
	}
	tags, err := normalizeTags([]string{tagRaw})
	if err != nil {
		return nil, err
	}
	if err := s.auth.ChangeRoleTag(ctx, actor, role, tags[0], add); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) RenameRoleTag(ctx context.Context, req *authv1.RenameRoleTagRequest) (*emptypb.Empty, error) {
	actor, role, err := actorAndRole(ctx, req.GetRoleId())
	if err != nil {
		return nil, err
	}
	oldTags, err := normalizeTags([]string{req.GetOldTag()})
	if err != nil {
		return nil, err
	}
	newTags, err := normalizeTags([]string{req.GetNewTag()})
	if err != nil {
		return nil, err
	}
	if err := s.auth.RenameRoleTag(ctx, actor, role, oldTags[0], newTags[0]); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) ListUserRoles(ctx context.Context, req *authv1.ListUserRolesRequest) (*authv1.ListUserRolesResponse, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	target, err := parseID("user_id", req.GetUserId())
	if err != nil {
		return nil, err
	}
	roles, err := s.auth.UserRoles(ctx, actor, target)
	if err != nil {
		return nil, err
	}
	out := make([]*authv1.UserRole, 0, len(roles))
	for _, role := range roles {
		out = append(out, pbUserRole(role))
	}
	return &authv1.ListUserRolesResponse{UserRoles: out}, nil
}

func (s *Server) ListRoleMembers(ctx context.Context, req *authv1.ListRoleMembersRequest) (*authv1.ListRoleMembersResponse, error) {
	actor, role, err := actorAndRole(ctx, req.GetRoleId())
	if err != nil {
		return nil, err
	}
	members, err := s.auth.RoleMembers(ctx, actor, role)
	if err != nil {
		return nil, err
	}
	out := make([]*authv1.RoleMember, 0, len(members))
	for _, member := range members {
		row := &authv1.RoleMember{UserId: member.UserID.String(), Login: member.Login, Level: pbRoleLevel(member.Level), Tags: member.Tags}
		if member.Email != nil {
			row.Email = member.Email
		}
		out = append(out, row)
	}
	return &authv1.ListRoleMembersResponse{Members: out}, nil
}

func (s *Server) AssignRole(ctx context.Context, req *authv1.AssignRoleRequest) (*emptypb.Empty, error) {
	actor, role, err := actorAndRole(ctx, req.GetRoleId())
	if err != nil {
		return nil, err
	}
	target, err := parseID("user_id", req.GetUserId())
	if err != nil {
		return nil, err
	}
	level, err := domainRoleLevel(req.GetLevel())
	if err != nil {
		return nil, err
	}
	validUntil, err := optionalTime(req.ValidUntil, "valid_until")
	if err != nil {
		return nil, err
	}
	tags, err := normalizeTags(req.GetTagGrants())
	if err != nil {
		return nil, err
	}
	if err := s.auth.AssignRole(ctx, actor, target, role, level, validUntil, tags); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) GrantMembershipTag(ctx context.Context, req *authv1.GrantMembershipTagRequest) (*emptypb.Empty, error) {
	return s.changeMembershipTag(ctx, req.GetRoleId(), req.GetUserId(), req.GetTag(), true)
}

func (s *Server) RevokeMembershipTag(ctx context.Context, req *authv1.RevokeMembershipTagRequest) (*emptypb.Empty, error) {
	return s.changeMembershipTag(ctx, req.GetRoleId(), req.GetUserId(), req.GetTag(), false)
}

func (s *Server) changeMembershipTag(ctx context.Context, roleRaw, userRaw, tagRaw string, add bool) (*emptypb.Empty, error) {
	actor, role, err := actorAndRole(ctx, roleRaw)
	if err != nil {
		return nil, err
	}
	target, err := parseID("user_id", userRaw)
	if err != nil {
		return nil, err
	}
	tags, err := normalizeTags([]string{tagRaw})
	if err != nil {
		return nil, err
	}
	if err := s.auth.ChangeMembershipTag(ctx, actor, target, role, tags[0], add); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) RemoveRole(ctx context.Context, req *authv1.RemoveRoleRequest) (*emptypb.Empty, error) {
	actor, role, err := actorAndRole(ctx, req.GetRoleId())
	if err != nil {
		return nil, err
	}
	target, err := parseID("user_id", req.GetUserId())
	if err != nil {
		return nil, err
	}
	if err := s.auth.RemoveRole(ctx, actor, target, role); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) RequestRole(ctx context.Context, req *authv1.RequestRoleRequest) (*authv1.RequestRoleResponse, error) {
	actor, role, err := actorAndRole(ctx, req.GetRoleId())
	if err != nil {
		return nil, err
	}
	target := actor
	if strings.TrimSpace(req.GetTargetUserId()) != "" {
		target, err = parseID("target_user_id", req.GetTargetUserId())
		if err != nil {
			return nil, err
		}
	}
	granted, id, err := s.auth.RequestRole(ctx, actor, target, role)
	if err != nil {
		return nil, err
	}
	if granted {
		return &authv1.RequestRoleResponse{Outcome: &authv1.RequestRoleResponse_Granted{Granted: &emptypb.Empty{}}}, nil
	}
	return &authv1.RequestRoleResponse{Outcome: &authv1.RequestRoleResponse_PendingRequestId{PendingRequestId: id.String()}}, nil
}

func (s *Server) ListRoleRequests(ctx context.Context, req *authv1.ListRoleRequestsRequest) (*authv1.ListRoleRequestsResponse, error) {
	actor, role, err := actorAndRole(ctx, req.GetRoleId())
	if err != nil {
		return nil, err
	}
	requests, err := s.auth.PendingRoleRequests(ctx, actor, role)
	if err != nil {
		return nil, err
	}
	out := make([]*authv1.RoleRequest, 0, len(requests))
	for _, request := range requests {
		out = append(out, pbRoleRequest(request))
	}
	return &authv1.ListRoleRequestsResponse{Requests: out}, nil
}

func (s *Server) DecideRoleRequest(ctx context.Context, req *authv1.DecideRoleRequestRequest) (*emptypb.Empty, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return nil, err
	}
	requestID, err := parseID("request_id", req.GetRequestId())
	if err != nil {
		return nil, err
	}
	if err := s.auth.DecideRoleRequest(ctx, actor, requestID, req.GetApprove()); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func actorAndRole(ctx context.Context, raw string) (uuid.UUID, uuid.UUID, error) {
	actor, err := actorFromContext(ctx)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	role, err := parseID("role_id", raw)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return actor, role, nil
}

func pbUserRole(role domain.UserRole) *authv1.UserRole {
	out := &authv1.UserRole{Id: role.ID.String(), UserId: role.UserID.String(), RoleId: role.RoleID.String(), Level: pbRoleLevel(role.Level), ValidFrom: pbTimestamp(role.ValidFrom)}
	if role.ValidUntil != nil {
		out.ValidUntil = pbTimestamp(*role.ValidUntil)
	}
	if role.GrantedBy != nil {
		value := role.GrantedBy.String()
		out.GrantedBy = &value
	}
	return out
}

func pbRoleRequest(request repository.RoleRequest) *authv1.RoleRequest {
	status := authv1.RoleRequestStatus_ROLE_REQUEST_STATUS_UNSPECIFIED
	switch request.Status {
	case domain.RoleRequestPending:
		status = authv1.RoleRequestStatus_ROLE_REQUEST_STATUS_PENDING
	case domain.RoleRequestApproved:
		status = authv1.RoleRequestStatus_ROLE_REQUEST_STATUS_APPROVED
	case domain.RoleRequestRejected:
		status = authv1.RoleRequestStatus_ROLE_REQUEST_STATUS_REJECTED
	}
	out := &authv1.RoleRequest{Id: request.ID.String(), RequesterId: request.RequesterID.String(), TargetUserId: request.TargetUserID.String(), RoleId: request.RoleID.String(), Status: status}
	if request.DecidedBy != nil {
		value := request.DecidedBy.String()
		out.DecidedBy = &value
	}
	return out
}
