package service

import "testing"

func TestPasswordsTooClose(t *testing.T) {
	if !PasswordsTooClose("hello", []string{"hallo"}, 1) {
		t.Fatal("expected close passwords to match within distance 1")
	}
	if PasswordsTooClose("hello", []string{"zzzzz"}, 1) {
		t.Fatal("expected unrelated passwords not to match")
	}
	if !PasswordsTooClose("a", []string{"a"}, 0) {
		t.Fatal("identical password should be too close at distance 0")
	}
}
