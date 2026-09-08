package service

import (
	"fmt"
	"net/url"
	"strings"
)

// oneTimeCallbackURL adds the token to either a normal callback query or an
// SPA hash-route query. Existing allowlisted callback parameters are retained.
func oneTimeCallbackURL(configured, fallback, token string) (string, error) {
	raw := strings.TrimSpace(configured)
	if raw == "" {
		raw = fallback
	}
	callback, err := url.Parse(raw)
	if err != nil || callback.Host == "" || (callback.Scheme != "http" && callback.Scheme != "https") {
		return "", fmt.Errorf("invalid callback URL")
	}
	if callback.Fragment == "" {
		query := callback.Query()
		query.Set("token", token)
		callback.RawQuery = query.Encode()
		return callback.String(), nil
	}
	fragmentPath, fragmentQuery, _ := strings.Cut(callback.Fragment, "?")
	query, err := url.ParseQuery(fragmentQuery)
	if err != nil {
		return "", fmt.Errorf("invalid callback fragment query: %w", err)
	}
	query.Set("token", token)
	callback.Fragment = fragmentPath + "?" + query.Encode()
	return callback.String(), nil
}
