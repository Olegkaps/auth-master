package service

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/crypto"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/olegkapshai/auth-master/internal/jwtutil"
	"github.com/olegkapshai/auth-master/internal/mail"
	"github.com/stretchr/testify/require"
)

func TestIntegration_MagicLinkLogin(t *testing.T) {
	repo, done := testDB(t)
	defer done()
	ctx := context.Background()
	a, err := NewAuth(testConfig(), repo, &mail.Sender{Host: "localhost", Port: 1025, From: "t@test.dev"}, nil)
	require.NoError(t, err)
	require.NoError(t, a.EnsureBootstrap(ctx))

	inv := seedSuperInvite(t, a, repo, ctx)
	uid, err := a.Register(ctx, inv, "magic", "magic@test.dev", "Magic-Pass-1!")
	require.NoError(t, err)

	// Unknown login is a silent no-op.
	require.NoError(t, a.StartMagicLink(ctx, "nobody"))

	// Inject a magic link (as StartMagicLink would) with a known raw token.
	raw, err := crypto.RandomBytes(32)
	require.NoError(t, err)
	token := hex.EncodeToString(raw)
	_, err = repo.InsertMagicLink(ctx, hashRefreshToken(token), uid, time.Now().Add(time.Minute))
	require.NoError(t, err)

	// Wrong token → invalid.
	_, _, err = a.CompleteMagicLink(ctx, "deadbeef", "dev-magic", "browser")
	require.ErrorIs(t, err, ErrOTPInvalid)

	// Correct token issues a session.
	tokens, u, err := a.CompleteMagicLink(ctx, token, "dev-magic", "browser")
	require.NoError(t, err)
	require.NotNil(t, tokens)
	require.Equal(t, uid, u.ID)
	require.NotEmpty(t, tokens.AccessToken)

	roleID, err := repo.CreateRole(ctx, "magic-role", "", nil)
	require.NoError(t, err)
	require.NoError(t, repo.AssignUserRole(ctx, uid, roleID, domain.RoleMember, &uid, time.Now(), nil))

	// A ban is enforced consistently by role checks, signed-token validation,
	// and magic-link completion, even if credentials predate the ban.
	rawBanned, err := crypto.RandomBytes(32)
	require.NoError(t, err)
	bannedToken := hex.EncodeToString(rawBanned)
	_, err = repo.InsertMagicLink(ctx, hashRefreshToken(bannedToken), uid, time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.NoError(t, repo.SetUserBan(ctx, uid, &uid, "test ban"))
	hasRole, err := a.UserHasRoleName(ctx, uid, "magic-role")
	require.ErrorIs(t, err, ErrBanned)
	require.False(t, hasRole)
	_, err = a.VerifyAccessToken(ctx, tokens.AccessToken, jwtutil.TypeAccess)
	require.ErrorIs(t, err, ErrBanned)
	_, _, err = a.CompleteMagicLink(ctx, bannedToken, "dev-banned", "browser")
	require.ErrorIs(t, err, ErrBanned)
	require.NoError(t, repo.SetUserBan(ctx, uid, nil, ""))

	// The link is single-use — replay fails.
	_, _, err = a.CompleteMagicLink(ctx, token, "dev-magic", "browser")
	require.ErrorIs(t, err, ErrOTPInvalid)

	require.NotEqual(t, uuid.Nil, u.ID)
}
