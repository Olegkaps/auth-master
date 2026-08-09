package service

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/crypto"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestBootstrapSuperuserServiceMatchPolicy(t *testing.T) {
	const secret = "Demo-Service-Secret1!"
	hash, err := crypto.HashSecret(secret)
	require.NoError(t, err)
	base := domain.User{ID: uuid.New(), Kind: domain.UserService, Superuser: true, ServiceSecretHash: &hash}
	require.NoError(t, bootstrapSuperuserServiceMatches(&base, secret))

	tests := []struct {
		name string
		edit func(*domain.User)
		want string
	}{
		{name: "human collision", edit: func(u *domain.User) { u.Kind = domain.UserHuman }, want: "incompatible account"},
		{name: "ordinary service collision", edit: func(u *domain.User) { u.Superuser = false }, want: "incompatible account"},
		{name: "missing hash", edit: func(u *domain.User) { u.ServiceSecretHash = nil }, want: "incompatible account"},
		{name: "banned", edit: func(u *domain.User) { now := time.Now(); u.BannedAt = &now }, want: "incompatible account"},
		{name: "secret mismatch", edit: func(*domain.User) {}, want: "credentials do not match"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			user := base
			test.edit(&user)
			candidate := secret
			if test.name == "secret mismatch" {
				candidate = "Different-Service-Secret1!"
			}
			err := bootstrapSuperuserServiceMatches(&user, candidate)
			require.ErrorContains(t, err, test.want)
		})
	}
}
