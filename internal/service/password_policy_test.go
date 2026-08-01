package service

import (
	"errors"
	"testing"
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
