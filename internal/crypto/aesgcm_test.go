package crypto

import (
	"bytes"
	"testing"
)

func TestAESGCM_roundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	pt := []byte("hello password plaintext")
	n, ct, err := EncryptAESGCM(key, pt, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecryptAESGCM(key, n, ct, []byte("aad"))
	if err != nil || !bytes.Equal(out, pt) {
		t.Fatal(err, out)
	}
}
