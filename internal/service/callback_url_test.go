package service

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOneTimeCallbackURL(t *testing.T) {
	t.Run("configured browser route retains query", func(t *testing.T) {
		got, err := oneTimeCallbackURL("https://app.example/admit?source=mail", "", "a+b/c")
		require.NoError(t, err)
		parsed, err := url.Parse(got)
		require.NoError(t, err)
		require.Equal(t, "/admit", parsed.Path)
		require.Equal(t, "mail", parsed.Query().Get("source"))
		require.Equal(t, "a+b/c", parsed.Query().Get("token"))
	})

	t.Run("fallback SPA hash route keeps token inside fragment", func(t *testing.T) {
		got, err := oneTimeCallbackURL("", "http://localhost:5173/#/magic?add=1", "token-value")
		require.NoError(t, err)
		parsed, err := url.Parse(got)
		require.NoError(t, err)
		require.Empty(t, parsed.Query().Get("token"))
		path, rawQuery, found := strings.Cut(parsed.Fragment, "?")
		require.True(t, found)
		require.Equal(t, "/magic", path)
		fragmentQuery, err := url.ParseQuery(rawQuery)
		require.NoError(t, err)
		require.Equal(t, "1", fragmentQuery.Get("add"))
		require.Equal(t, "token-value", fragmentQuery.Get("token"))
	})

	t.Run("invalid URL fails closed", func(t *testing.T) {
		_, err := oneTimeCallbackURL("javascript:alert(1)", "", "token")
		require.Error(t, err)
	})
}
