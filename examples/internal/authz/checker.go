package authz

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

var ErrMissingBearer = errors.New("missing bearer access token")

// Checker is the small cross-service authorization surface used by the
// examples. The access token belongs to the human caller being evaluated.
type Checker interface {
	HasRole(context.Context, string, string) (bool, error)
	HasRoleWithTag(context.Context, string, string, string) (bool, error)
}

func BearerToken(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", ErrMissingBearer
	}
	parts := strings.Split(values[0], " ")
	if len(parts) != 2 || parts[0] != "Bearer" || strings.TrimSpace(parts[1]) == "" {
		return "", ErrMissingBearer
	}
	return parts[1], nil
}

// SubjectVerifier verifies a human access token and returns its user ID.
type SubjectVerifier interface {
	VerifySubject(context.Context, string) (string, error)
}
