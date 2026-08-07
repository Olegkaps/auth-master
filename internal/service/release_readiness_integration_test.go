package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/stretchr/testify/require"
)

func TestIntegration_RegistrationInviteIsClaimedAtomically(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	auth, err := NewAuth(testConfig(), repo, &mail.Sender{}, nil)
	require.NoError(t, err)
	invite := seedSuperInvite(t, auth, repo, ctx)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, login := range []string{"invite-race-a", "invite-race-b"} {
		login := login
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, registerErr := auth.Register(ctx, invite, login, login+"@test.dev", "Invite-Race-11!")
			errs <- registerErr
		}()
	}
	wg.Wait()
	close(errs)
	succeeded := 0
	for registerErr := range errs {
		if registerErr == nil {
			succeeded++
		}
	}
	require.Equal(t, 1, succeeded, "a one-time invite must create exactly one account")
}

func TestIntegration_RoleWritesAreAtomicValidatedAndCycleSafe(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	suffix := uuid.NewString()

	parentA, err := repo.CreateRole(ctx, "parent-a-"+suffix, "", nil)
	require.NoError(t, err)
	parentB, err := repo.CreateRole(ctx, "parent-b-"+suffix, "", nil)
	require.NoError(t, err)
	childName := "atomic-child-" + suffix
	child, err := repo.CreateRoleWithParents(ctx, childName, "", []uuid.UUID{parentA, uuid.New()})
	require.Error(t, err)
	require.Equal(t, uuid.Nil, child)
	missing, err := repo.GetRoleByName(ctx, childName)
	require.NoError(t, err)
	require.Nil(t, missing, "invalid parents must not leave a partial role")

	child, err = repo.CreateRoleWithParents(ctx, childName, "", []uuid.UUID{parentA, parentB})
	require.NoError(t, err)
	created, err := repo.GetRoleByID(ctx, child)
	require.NoError(t, err)
	require.ElementsMatch(t, []uuid.UUID{parentA, parentB}, created.ParentIDs)

	_, err = repo.CreateRole(ctx, " ", "", nil)
	require.Error(t, err)
	_, err = repo.CreateRole(ctx, "ATOMIC-CHILD-"+suffix, "", nil)
	require.Error(t, err, "role names must be unique without case ambiguity")

	left, err := repo.CreateRole(ctx, "cycle-left-"+suffix, "", nil)
	require.NoError(t, err)
	right, err := repo.CreateRole(ctx, "cycle-right-"+suffix, "", nil)
	require.NoError(t, err)
	results := make(chan error, 2)
	go func() { results <- repo.MountRole(ctx, left, right) }()
	go func() { results <- repo.MountRole(ctx, right, left) }()
	first, second := <-results, <-results
	require.NotEqual(t, first == nil, second == nil, "exactly one opposing mount may commit")
	leftHasRight, err := repo.RoleHasAncestor(ctx, left, right)
	require.NoError(t, err)
	rightHasLeft, err := repo.RoleHasAncestor(ctx, right, left)
	require.NoError(t, err)
	require.False(t, leftHasRight && rightHasLeft, "concurrent writes must not create a cycle")
}

func TestIntegration_RoleRequestsAccessAndTagAssignmentAreAtomic(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	auth, err := NewAuth(testConfig(), repo, &mail.Sender{}, nil)
	require.NoError(t, err)
	suffix := uuid.NewString()
	actor, err := repo.CreateHumanUser(ctx, "requester-"+suffix, "requester-"+suffix+"@test.dev", "hash")
	require.NoError(t, err)
	stranger, err := repo.CreateHumanUser(ctx, "stranger-"+suffix, "stranger-"+suffix+"@test.dev", "hash")
	require.NoError(t, err)
	roleID, err := repo.CreateRole(ctx, "request-role-"+suffix, "", nil)
	require.NoError(t, err)

	_, _, err = auth.RequestRoleMembership(ctx, actor, stranger, roleID)
	require.ErrorIs(t, err, ErrForbidden)
	granted, requestID, err := auth.RequestRoleMembership(ctx, actor, actor, roleID)
	require.NoError(t, err)
	require.False(t, granted)

	admin, err := repo.CreateHumanUser(ctx, "request-admin-"+suffix, "request-admin-"+suffix+"@test.dev", "hash")
	require.NoError(t, err)
	require.NoError(t, repo.DecideRoleRequestWithMembership(ctx, requestID, true, admin, time.Now()))
	level, found, err := repo.GetUserRoleLevel(ctx, actor, roleID, time.Now())
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, domain.RoleMember, level)

	taggedRole, err := repo.CreateRole(ctx, "tag-role-"+suffix, "", nil)
	require.NoError(t, err)
	require.NoError(t, repo.AddRoleTag(ctx, taggedRole, "read"))
	err = repo.AssignUserRoleWithTagGrants(ctx, stranger, taggedRole, domain.RoleMember, &admin, time.Now(), nil, []string{"read", "missing"})
	require.Error(t, err)
	_, found, err = repo.GetUserRoleLevel(ctx, stranger, taggedRole, time.Now())
	require.NoError(t, err)
	require.False(t, found, "invalid initial grants must roll back membership")
	require.NoError(t, repo.AssignUserRoleWithTagGrants(ctx, stranger, taggedRole, domain.RoleMember, &admin, time.Now(), nil, []string{"read"}))
	hasTag, err := auth.UserHasRoleWithTag(ctx, stranger, "tag-role-"+suffix, "read")
	require.NoError(t, err)
	require.True(t, hasTag)
}

func TestIntegration_EffectiveRoleAccessMirrorsInheritance(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	suffix := uuid.NewString()
	userID, err := repo.CreateHumanUser(ctx, "access-"+suffix, "access-"+suffix+"@test.dev", "hash")
	require.NoError(t, err)
	parent, err := repo.CreateRole(ctx, "access-parent-"+suffix, "", nil)
	require.NoError(t, err)
	child, err := repo.CreateRole(ctx, "access-child-"+suffix, "", &parent)
	require.NoError(t, err)

	require.NoError(t, repo.AssignUserRole(ctx, userID, parent, domain.RoleDirectMember, &userID, time.Now(), nil))
	access, err := repo.ListEffectiveRoleAccess(ctx, userID, time.Now())
	require.NoError(t, err)
	require.Len(t, access, 1)
	require.Equal(t, parent, access[0].RoleID)

	require.NoError(t, repo.AssignUserRole(ctx, userID, parent, domain.RoleRoleAdmin, &userID, time.Now(), nil))
	access, err = repo.ListEffectiveRoleAccess(ctx, userID, time.Now())
	require.NoError(t, err)
	byRole := make(map[uuid.UUID]bool, len(access))
	for _, item := range access {
		byRole[item.RoleID] = item.CanManage
	}
	require.True(t, byRole[parent])
	require.True(t, byRole[child], "role-admin UI authority must inherit to descendants")
}

func TestIntegration_PasswordResetThrottleAndAttemptCap(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	cfg := testConfig()
	cfg.OTPMaxAttempts = 3
	cfg.OTPResetMinInterval = time.Hour
	auth, err := NewAuth(cfg, repo, &mail.Sender{}, nil)
	require.NoError(t, err)
	invite := seedSuperInvite(t, auth, repo, ctx)
	userID, err := auth.Register(ctx, invite, "reset-limited", "reset-limited@test.dev", "Old-Reset-11!")
	require.NoError(t, err)

	code := "246810"
	otpID, err := repo.CreateEmailOTP(ctx, userID, domain.OTPPasswordReset, auth.IntegrationOTPHash(code), time.Now().Add(time.Hour), nil)
	require.NoError(t, err)
	require.NoError(t, auth.StartPasswordReset(ctx, "reset-limited"))
	latest, err := repo.GetMostRecentOTP(ctx, userID, domain.OTPPasswordReset)
	require.NoError(t, err)
	require.Equal(t, otpID, latest.ID, "a throttled request must not mint or email another OTP")

	for range cfg.OTPMaxAttempts {
		require.ErrorIs(t, auth.ResetPasswordWithOTP(ctx, "reset-limited", "000000", "New-Reset-22!"), ErrOTPInvalid)
	}
	require.ErrorIs(t, auth.ResetPasswordWithOTP(ctx, "reset-limited", code, "New-Reset-22!"), ErrOTPInvalid, "correct code must fail after the attempt cap")
}
