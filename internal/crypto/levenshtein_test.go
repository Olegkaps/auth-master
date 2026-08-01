package crypto

import "testing"

func TestLevenshtein(t *testing.T) {
	if Levenshtein("", "") != 0 {
		t.Fatal()
	}
	if Levenshtein("abc", "abc") != 0 {
		t.Fatal()
	}
	if Levenshtein("kitten", "sitting") != 3 {
		t.Fatalf("got %d", Levenshtein("kitten", "sitting"))
	}
	if Levenshtein("a", "bc") != 2 {
		t.Fatal()
	}
}
