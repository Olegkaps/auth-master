package crypto

import "testing"

func TestHashVerifyPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword("correct horse battery staple", h)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	ok, err = VerifyPassword("wrong", h)
	if err != nil || ok {
		t.Fatal(ok, err)
	}
}

func TestHashSecret(t *testing.T) {
	h, err := HashSecret("svc-secret")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifySecret("svc-secret", h)
	if err != nil || !ok {
		t.Fatal()
	}
	ok, err = VerifySecret("svc-secret-wrong", h)
	if err != nil || ok {
		t.Fatal(ok, err)
	}
}
