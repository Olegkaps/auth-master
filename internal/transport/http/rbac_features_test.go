package httptransport

import (
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/stretchr/testify/require"
)

func TestPaginationAndTagNormalization(t *testing.T) {
	for _, tc := range []struct {
		name     string
		query    string
		wantSize int
	}{
		{name: "explicit", query: "?page_size=50", wantSize: 50},
		{name: "defaults", query: "", wantSize: 25},
		{name: "reject oversized", query: "?page_size=101", wantSize: 25},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/"+tc.query, nil)
			require.Equal(t, tc.wantSize, pageSize(req))
		})
	}

	t.Run("cursor round trip", func(t *testing.T) {
		original := &repository.PageCursor{Sort: "alice", ID: uuid.New()}
		decoded, err := decodeCursor(encodeCursor(original))
		require.NoError(t, err)
		require.Equal(t, original, decoded)
	})
	t.Run("invalid cursor rejected", func(t *testing.T) {
		_, err := decodeCursor("not-base64")
		require.Error(t, err)
	})

	t.Run("tags normalize and deduplicate", func(t *testing.T) {
		tags, err := normalizeTags([]string{" Read ", "read", "WRITE"})
		require.NoError(t, err)
		require.Equal(t, []string{"read", "write"}, tags)
	})
	t.Run("empty tag rejected", func(t *testing.T) {
		_, err := normalizeTags([]string{""})
		require.Error(t, err)
	})
	t.Run("long tag rejected", func(t *testing.T) {
		_, err := normalizeTags([]string{"12345678901234567890123456789012345678901234567890123456789012345"})
		require.Error(t, err)
	})
	t.Run("too many tags rejected", func(t *testing.T) {
		tags := make([]string, 33)
		for i := range tags {
			tags[i] = "tag"
		}
		_, err := normalizeTags(tags)
		require.Error(t, err)
	})

	t.Run("rename preserves old and new tag direction", func(t *testing.T) {
		oldTag, newTag, err := normalizeRoleTagRename(" Read ", "VIEW")
		require.NoError(t, err)
		require.Equal(t, "read", oldTag)
		require.Equal(t, "view", newTag)
	})
}

func TestNormalizeTokenRoleCheck(t *testing.T) {
	token, role, tag, err := normalizeTokenRoleCheck(tokenRoleCheckBody{Token: " token ", RoleName: " editors ", Tag: " read "}, true)
	require.NoError(t, err)
	require.Equal(t, "token", token)
	require.Equal(t, "editors", role)
	require.Equal(t, "read", tag)

	_, _, _, err = normalizeTokenRoleCheck(tokenRoleCheckBody{Token: "token", RoleName: "editors"}, true)
	require.Error(t, err)
	_, _, _, err = normalizeTokenRoleCheck(tokenRoleCheckBody{RoleName: "editors"}, false)
	require.Error(t, err)
}

func TestNormalizeRoleName(t *testing.T) {
	name, err := normalizeRoleName("  Engineering  ")
	require.NoError(t, err)
	require.Equal(t, "Engineering", name)

	_, err = normalizeRoleName("   ")
	require.Error(t, err)
	_, err = normalizeRoleName(string(make([]byte, 101)))
	require.Error(t, err)
}
