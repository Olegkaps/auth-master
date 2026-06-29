package jwtutil

import "testing"

func FuzzParseUnverifiedClaims(f *testing.F) {
	f.Add("a.b.c")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			t.Skip()
		}
		_, _ = ParseUnverifiedClaims(s)
	})
}
