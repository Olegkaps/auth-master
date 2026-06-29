package jwtutil

import (
	"testing"
	"time"

	"github.com/olegkapshai/auth-master/internal/crypto"
)

func TestSignParseAccess(t *testing.T) {
	key, err := crypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := SignAccess(key, "kid1", "user-uuid", "alice", TypeAccess, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	uv, err := ParseUnverifiedClaims(tok)
	if err != nil || uv.Login != "alice" || uv.Kid != "kid1" || uv.Typ != TypeAccess {
		t.Fatalf("%+v %v", uv, err)
	}
	v, err := ParseAndVerify(tok, key)
	if err != nil || v.Subject != "user-uuid" {
		t.Fatal(err, v)
	}
}

func TestSignWrongTyp(t *testing.T) {
	key := make([]byte, 32)
	_, err := SignAccess(key, "k", "u", "l", "bogus", time.Minute)
	if err == nil {
		t.Fatal()
	}
}
