package grpctransport

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/repository"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func parseID(field, value string) (uuid.UUID, error) {
	id, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil {
		return uuid.Nil, invalid(field, "must be a UUID")
	}
	return id, nil
}

func normalizeText(field, value string, max int) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > max {
		return "", invalid(field, "must contain 1 to "+itoa(max)+" characters")
	}
	return value, nil
}

func itoa(n int) string {
	if n == 100 {
		return "100"
	}
	if n == 64 {
		return "64"
	}
	return "32"
}

func normalizeTags(tags []string) ([]string, error) {
	if len(tags) > 32 {
		return nil, invalid("tags", "at most 32 tags are allowed")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(tags))
	for _, raw := range tags {
		tag, err := normalizeText("tag", strings.ToLower(raw), 64)
		if err != nil {
			return nil, err
		}
		if !seen[tag] {
			seen[tag] = true
			out = append(out, tag)
		}
	}
	return out, nil
}

func decodeCursor(raw string) (*repository.PageCursor, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, invalid("cursor", "invalid opaque cursor")
	}
	var cursor repository.PageCursor
	if json.Unmarshal(data, &cursor) != nil || cursor.Sort == "" || cursor.ID == uuid.Nil {
		return nil, invalid("cursor", "invalid opaque cursor")
	}
	return &cursor, nil
}

func encodeCursor(cursor *repository.PageCursor) string {
	if cursor == nil {
		return ""
	}
	raw, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func page(in *authv1.PageRequest) (string, *repository.PageCursor, int, error) {
	if in == nil {
		return "", nil, 25, nil
	}
	size := int(in.GetPageSize())
	if size == 0 {
		size = 25
	}
	if size < 1 || size > 100 {
		return "", nil, 0, invalid("page_size", "must be between 1 and 100")
	}
	cursor, err := decodeCursor(in.GetCursor())
	return strings.TrimSpace(in.GetQuery()), cursor, size, err
}

func pbUser(u domain.User) *authv1.User {
	out := &authv1.User{Id: u.ID.String(), Login: u.Login, Kind: pbUserKind(u.Kind), Superuser: u.Superuser, BanReason: u.BanReason, CreatedAt: timestamppb.New(u.CreatedAt)}
	if u.Email != nil {
		out.Email = u.Email
	}
	if u.BannedAt != nil {
		out.BannedAt = timestamppb.New(*u.BannedAt)
	}
	return out
}

func pbUserKind(kind domain.UserKind) authv1.UserKind {
	if kind == domain.UserService {
		return authv1.UserKind_USER_KIND_SERVICE
	}
	return authv1.UserKind_USER_KIND_HUMAN
}

func pbRole(r domain.Role) *authv1.Role {
	parents := make([]string, 0, len(r.ParentIDs))
	for _, id := range r.ParentIDs {
		parents = append(parents, id.String())
	}
	return &authv1.Role{Id: r.ID.String(), Name: r.Name, Description: r.Description, ParentIds: parents, Tags: r.Tags, CreatedAt: timestamppb.New(r.CreatedAt)}
}

func pbRoleLevel(level domain.RoleLevel) authv1.RoleLevel {
	switch level {
	case domain.RoleDirectMember:
		return authv1.RoleLevel_ROLE_LEVEL_DIRECT_MEMBER
	case domain.RoleMember:
		return authv1.RoleLevel_ROLE_LEVEL_MEMBER
	case domain.RoleRoleAdmin:
		return authv1.RoleLevel_ROLE_LEVEL_ROLE_ADMIN
	default:
		return authv1.RoleLevel_ROLE_LEVEL_UNSPECIFIED
	}
}

func domainRoleLevel(level authv1.RoleLevel) (domain.RoleLevel, error) {
	switch level {
	case authv1.RoleLevel_ROLE_LEVEL_DIRECT_MEMBER:
		return domain.RoleDirectMember, nil
	case authv1.RoleLevel_ROLE_LEVEL_MEMBER:
		return domain.RoleMember, nil
	case authv1.RoleLevel_ROLE_LEVEL_ROLE_ADMIN:
		return domain.RoleRoleAdmin, nil
	default:
		return "", invalid("level", "must be DIRECT_MEMBER, MEMBER, or ROLE_ADMIN")
	}
}

func pbTimestamp(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }

func optionalTime(in *timestamppb.Timestamp, field string) (*time.Time, error) {
	if in == nil {
		return nil, nil
	}
	if err := in.CheckValid(); err != nil {
		return nil, invalid(field, "invalid timestamp")
	}
	t := in.AsTime()
	return &t, nil
}
