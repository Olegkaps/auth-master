package service

import "github.com/olegkapshai/auth-master/internal/crypto"

// PasswordsTooClose reports whether newPwd is within maxEditDistance (inclusive) of any previous plaintext.
func PasswordsTooClose(newPwd string, previous []string, maxEditDistance int) bool {
	for _, p := range previous {
		if crypto.Levenshtein(newPwd, p) <= maxEditDistance {
			return true
		}
	}
	return false
}
