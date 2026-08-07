package service

import (
	"errors"
	"testing"

	"github.com/olegkapshai/auth-master/internal/crypto"
	"github.com/olegkapshai/auth-master/internal/repository"
	"github.com/stretchr/testify/require"
)

func TestCheckPasswordComplexity(t *testing.T) {
	cases := []struct {
		name string
		pw   string
		ok   bool
	}{
		{"valid", "Str0ng!Pass", true},
		{"too short", "Ab1!", false},
		{"no upper", "str0ng!pass", false},
		{"no lower", "STR0NG!PASS", false},
		{"no digit", "Strong!Pass", false},
		{"no special", "Str0ngPass1", false},
		{"spaces are not special", "Strong Pass1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkPasswordComplexity(c.pw)
			if c.ok && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if !c.ok {
				if err == nil {
					t.Fatal("expected policy error, got nil")
				}
				if !errors.Is(err, ErrPasswordPolicy) {
					t.Fatalf("expected ErrPasswordPolicy, got %v", err)
				}
			}
		})
	}
}

func TestPreparePasswordResetMutation(t *testing.T) {
	key := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	oldPassword := "Old-Password-11!"
	oldHash, err := crypto.HashPassword(oldPassword)
	require.NoError(t, err)
	plainKey, err := crypto.DecodeKey32(key)
	require.NoError(t, err)
	nonce, cipher, err := crypto.EncryptAESGCM(plainKey, []byte(oldPassword), nil)
	require.NoError(t, err)
	history := []repository.PasswordHistoryEntry{{PasswordHash: oldHash, Ciphertext: cipher, Nonce: nonce}}

	mutation, err := preparePasswordResetMutation("Fresh-Password-22!", history, key)
	require.NoError(t, err)
	require.NotEmpty(t, mutation.PasswordHash)
	require.NotEmpty(t, mutation.Ciphertext)
	require.NotEmpty(t, mutation.Nonce)
	ok, err := crypto.VerifyPassword("Fresh-Password-22!", mutation.PasswordHash)
	require.NoError(t, err)
	require.True(t, ok)

	_, err = preparePasswordResetMutation("weak", history, key)
	require.ErrorIs(t, err, ErrPasswordPolicy)
	_, err = preparePasswordResetMutation(oldPassword, history, key)
	require.ErrorIs(t, err, ErrPasswordPolicy)
	_, err = preparePasswordResetMutation("Fresh-Password-22!", history, "invalid-key")
	require.Error(t, err)
}

func TestPasswordResetCompletionError(t *testing.T) {
	require.NoError(t, passwordResetCompletionError(true, nil))
	require.ErrorIs(t, passwordResetCompletionError(false, nil), ErrOTPInvalid)
	policyErr := errors.New("prepare failed")
	require.ErrorIs(t, passwordResetCompletionError(false, policyErr), policyErr)
}
