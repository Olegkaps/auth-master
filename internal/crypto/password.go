package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 2
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword returns an argon2id-encoded hash string.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return enc, nil
}

// VerifyPassword checks password against an encoded argon2id hash.
func VerifyPassword(password, encoded string) (bool, error) {
	salt, hash, err := parseArgon2ID(encoded)
	if err != nil {
		return false, err
	}
	cmp := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return subtle.ConstantTimeCompare(hash, cmp) == 1, nil
}

func parseArgon2ID(encoded string) (salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return nil, nil, errors.New("invalid argon2id encoding")
	}
	var m, t, p int
	for _, seg := range strings.Split(parts[2], ",") {
		kv := strings.SplitN(seg, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "m":
			m, _ = strconv.Atoi(kv[1])
		case "t":
			t, _ = strconv.Atoi(kv[1])
		case "p":
			p, _ = strconv.Atoi(kv[1])
		}
	}
	if m != argonMemory || t != argonTime || p != argonThreads {
		return nil, nil, errors.New("unsupported argon2 parameters")
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, nil, err
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, err
	}
	return salt, hash, nil
}

// HashSecret hashes a service secret (same format as password).
func HashSecret(secret string) (string, error) {
	return HashPassword(secret)
}

// VerifySecret checks secret against hash.
func VerifySecret(secret, encoded string) (bool, error) {
	return VerifyPassword(secret, encoded)
}
