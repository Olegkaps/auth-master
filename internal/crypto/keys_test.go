package crypto

import "testing"

func TestDecodeKey32_hex(t *testing.T) {
	// 32 bytes as hex
	s := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	b, err := DecodeKey32(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("hex: %v %d", err, len(b))
	}
}

func TestDecodeKey32_base64(t *testing.T) {
	s := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 * 0x00
	b, err := DecodeKey32(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 32 {
		t.Fatalf("len %d", len(b))
	}
}

func TestDecodeKey32_errors(t *testing.T) {
	if _, err := DecodeKey32(""); err == nil {
		t.Fatal()
	}
	if _, err := DecodeKey32("not-a-key"); err == nil {
		t.Fatal()
	}
}

func TestDecodeKey32_hex_wrongByteCount_notBase64(t *testing.T) {
	// 66 hex chars = 33 bytes; must not fall through to base64 (previously: "got 49").
	s := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	_, err := DecodeKey32(s)
	if err == nil {
		t.Fatal("expected error")
	}
}
