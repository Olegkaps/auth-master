package service

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"math/big"
)

func hashRefreshToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

func hashOTP(pepper []byte, code string) []byte {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(code))
	return mac.Sum(nil)
}

func otpCodesEqual(pepper []byte, code string, storedHash []byte) bool {
	return subtle.ConstantTimeCompare(hashOTP(pepper, code), storedHash) == 1
}

// IntegrationOTPHash returns the digest stored for a plaintext OTP code (HTTP / repository integration tests).
func (a *Auth) IntegrationOTPHash(code string) []byte {
	return hashOTP(a.otpPepper, code)
}

func randomRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func randomNumericCode(length int) (string, error) {
	const digits = "0123456789"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		b[i] = digits[n.Int64()]
	}
	return string(b), nil
}
