package crypto

import (
	"bytes"
	"testing"
)

func TestRandomBytes(t *testing.T) {
	b, err := RandomBytes(32)
	if err != nil || len(b) != 32 {
		t.Fatal("RandomBytes failed")
	}

	// Check randomness
	b2, _ := RandomBytes(32)
	if bytes.Equal(b, b2) {
		t.Fatal("RandomBytes not random")
	}
}

func TestHash(t *testing.T) {
	data := []byte("test")

	h1 := Hash("sha256", data)
	h2 := Hash("sha256", data)
	if !bytes.Equal(h1, h2) {
		t.Fatal("Hash not deterministic")
	}

	h3 := Hash("sha512", data)
	if bytes.Equal(h1, h3) {
		t.Fatal("Different algorithms gave same hash")
	}
}

func TestHMAC(t *testing.T) {
	key := []byte("key")
	data := []byte("data")

	mac1 := HMAC("sha256", key, data)
	mac2 := HMAC("sha256", key, data)
	if !bytes.Equal(mac1, mac2) {
		t.Fatal("HMAC not deterministic")
	}

	mac3 := HMAC("sha256", []byte("other"), data)
	if bytes.Equal(mac1, mac3) {
		t.Fatal("Different keys gave same HMAC")
	}
}

func TestSecureErase(t *testing.T) {
	data := []byte("sensitive")
	SecureErase(data)
	for _, b := range data {
		if b != 0 {
			t.Fatal("SecureErase failed")
		}
	}
}
