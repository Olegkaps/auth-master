package service

import (
	"context"
	"testing"
	"time"

	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/stretchr/testify/require"
)

func TestIntegration_SharedValidationPrecedesPersistence(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	auth, err := NewAuth(testConfig(), repo, &mail.Sender{}, nil)
	require.NoError(t, err)

	admin, err := repo.CreateHumanUser(ctx, "validation-admin", "validation-admin@test.dev", "hash")
	require.NoError(t, err)
	require.NoError(t, repo.SetSuperuser(ctx, admin, true))
	target, err := repo.CreateHumanUser(ctx, "validation-target", "validation-target@test.dev", "hash")
	require.NoError(t, err)
	role, err := repo.CreateRole(ctx, "validation-role", "", nil)
	require.NoError(t, err)
	future := time.Now().Add(time.Hour)
	require.NoError(t, auth.AssignRole(ctx, admin, target, role, domain.RoleMember, &future, nil))

	past := time.Now().Add(-time.Second)
	err = auth.AssignRole(ctx, admin, target, role, domain.RoleDirectMember, &past, nil)
	require.ErrorIs(t, err, ErrInvalidArgument)
	level, found, err := repo.GetUserRoleLevel(ctx, target, role, time.Now())
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, domain.RoleMember, level, "invalid assignment must not overwrite persisted membership")

	started := time.Now()
	correlation, err := auth.BeginStepUp2FA(ctx, target, 0)
	require.NoError(t, err)
	session, err := repo.GetStepUp2FA(ctx, correlation)
	require.NoError(t, err)
	require.WithinDuration(t, started.Add(DefaultStepUpTTL), session.ExpiresAt, 2*time.Second)
	_, err = auth.BeginStepUp2FA(ctx, target, -time.Nanosecond)
	require.ErrorIs(t, err, ErrInvalidArgument)

	_, expiresAt, _, err := auth.CreateRegistrationInvite(ctx, admin, nil, false, 0)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now().Add(DefaultInviteTTL), expiresAt, 2*time.Second)
	_, _, _, err = auth.CreateRegistrationInvite(ctx, admin, nil, false, -time.Nanosecond)
	require.ErrorIs(t, err, ErrInvalidArgument)
}
