package service

import "testing"

func TestHashRefreshToken_stable(t *testing.T) {
	a := hashRefreshToken("tok")
	b := hashRefreshToken("tok")
	if string(a) != string(b) {
		t.Fatal()
	}
}
