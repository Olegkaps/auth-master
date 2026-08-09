package authz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	authv1 "github.com/olegkapshai/auth-master/api/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// JWTSubjectVerifier rejects malformed compact JWTs before calling auth-master.
// This keeps credential syntax failures distinct from an upstream Internal error,
// which consumers must treat as an authentication-service outage.
type JWTSubjectVerifier struct {
	Verifier SubjectVerifier
}

func (v JWTSubjectVerifier) VerifySubject(ctx context.Context, token string) (string, error) {
	if !validCompactJWT(token) {
		return "", status.Error(codes.Unauthenticated, "invalid access token")
	}
	return v.Verifier.VerifySubject(ctx, token)
}

func validCompactJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false
	}
	for _, part := range parts {
		if _, err := base64.RawURLEncoding.DecodeString(part); err != nil {
			return false
		}
	}
	for _, part := range parts[:2] {
		decoded, _ := base64.RawURLEncoding.DecodeString(part)
		var object map[string]any
		if json.Unmarshal(decoded, &object) != nil || object == nil {
			return false
		}
	}
	return true
}

type GRPCChecker struct {
	Client  authv1.AuthServiceClient
	Timeout time.Duration
}

func (c GRPCChecker) HasRole(ctx context.Context, token, role string) (bool, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	response, err := c.Client.CheckTokenRole(ctx, &authv1.CheckTokenRoleRequest{
		AccessToken: token,
		RoleName:    role,
	})
	if err != nil {
		return false, err
	}
	return response.GetHasRole(), nil
}

func (c GRPCChecker) HasRoleWithTag(ctx context.Context, token, role, tag string) (bool, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	response, err := c.Client.CheckTokenRoleWithTag(ctx, &authv1.CheckTokenRoleWithTagRequest{
		AccessToken: token,
		RoleName:    role,
		Tag:         tag,
	})
	if err != nil {
		return false, err
	}
	return response.GetHasRoleWithTag(), nil
}

func (c GRPCChecker) VerifySubject(ctx context.Context, token string) (string, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	response, err := c.Client.VerifyAccessToken(ctx, &authv1.VerifyAccessTokenRequest{AccessToken: token})
	if err != nil {
		return "", err
	}
	return response.GetClaims().GetSubject(), nil
}

func (c GRPCChecker) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return context.WithTimeout(ctx, timeout)
}
