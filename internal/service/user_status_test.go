package service

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestRequireActiveUser(t *testing.T) {
	require.ErrorIs(t, requireActiveUser(nil), ErrInvalidCredentials)
	require.NoError(t, requireActiveUser(&domain.User{}))
	bannedAt := time.Now()
	require.ErrorIs(t, requireActiveUser(&domain.User{BannedAt: &bannedAt}), ErrBanned)
}

func TestValidateBanTarget(t *testing.T) {
	actorID := uuid.New()
	require.ErrorIs(t, validateBanTarget(actorID, nil), ErrNotFound)
	require.ErrorIs(t, validateBanTarget(actorID, &domain.User{ID: actorID}), ErrCannotBanSelf)
	require.ErrorIs(t, validateBanTarget(actorID, &domain.User{ID: uuid.New(), Superuser: true}), ErrCannotBanSuperuser)
	require.NoError(t, validateBanTarget(actorID, &domain.User{ID: uuid.New()}))
}
