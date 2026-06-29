package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// DecodeKey32 parses a 32-byte key from hex (64 hex chars) or standard base64.
func DecodeKey32(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty key")
	}
	// Prefer hex whenever the string is all-hex with even length, so a mistaken
	// 66-char dev key is not interpreted as base64 (which produced confusing lengths).
	if hexDecodable(s) && len(s)%2 == 0 {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("key: invalid hex: %w", err)
		}
		if len(b) != 32 {
			msg := fmt.Sprintf("key: hex must decode to 32 bytes (64 hex characters), got %d bytes", len(b))
			return nil, errors.New(msg)
		}
		return b, nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	if err != nil {
		return nil, fmt.Errorf("key: expected 64-char hex or base64-32-bytes: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("decoded key must be 32 bytes, got %d", len(b))
	}
	return b, nil
}

func hexDecodable(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// RandomBytes returns n random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
