package crypto

import "testing"

func FuzzLevenshtein(f *testing.F) {
	f.Add("a", "b")
	f.Add("", "xyz")
	f.Fuzz(func(t *testing.T, a, b string) {
		if len(a) > 256 || len(b) > 256 {
			t.Skip()
		}
		_ = Levenshtein(a, b)
	})
}
