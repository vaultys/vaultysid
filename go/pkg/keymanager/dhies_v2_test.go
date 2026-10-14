package keymanager

import (
	"bytes"
	"crypto/sha512"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
)

func fixedManager(t *testing.T, b byte) *Ed25519Manager {
	t.Helper()
	km, err := CreateFromEntropyInternal(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return km
}

// TestDHIESV2_KnownAnswer recomputes the DHIES v2 construction
// independently (spec §3) and checks the implementation's bytes.
func TestDHIESV2_KnownAnswer(t *testing.T) {
	alice := fixedManager(t, 0x01)
	bob := fixedManager(t, 0x02)
	ePriv := bytes.Repeat([]byte{0x03}, 32)
	var nonce [24]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	plaintext := []byte("Vaultys DHIES v2 known answer")

	out, err := dhiesEncryptV2Deterministic(ePriv, &nonce, alice.Cypher.SecretKey, alice.Cypher.PublicKey, bob.Cypher.PublicKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Independent recomputation.
	ePub, _ := curve25519.X25519(ePriv, curve25519.Basepoint)
	es, _ := curve25519.X25519(ePriv, bob.Cypher.PublicKey)
	ss, _ := curve25519.X25519(alice.Cypher.SecretKey, bob.Cypher.PublicKey)
	var material []byte
	material = append(material, es...)
	material = append(material, ss...)
	material = append(material, []byte("VAULTYS_DHIES_V2")...)
	material = append(material, ePub...)
	material = append(material, alice.Cypher.PublicKey...)
	material = append(material, bob.Cypher.PublicKey...)
	sum := sha512.Sum512(material)
	var k [32]byte
	copy(k[:], sum[:32])
	expected := append([]byte{0x02}, nonce[:]...)
	expected = append(expected, ePub...)
	expected = secretbox.Seal(expected, plaintext, &nonce, &k)

	if !bytes.Equal(out, expected) {
		t.Fatalf("DHIES v2 output mismatch\n got %x\nwant %x", out, expected)
	}
	if out[0] != 0x02 || len(out) != 1+24+32+len(plaintext)+16 {
		t.Fatalf("bad layout")
	}

	dec, err := DHIESDecryptV2(bob.Cypher.SecretKey, bob.Cypher.PublicKey, alice.Cypher.PublicKey, out)
	if err != nil || !bytes.Equal(dec, plaintext) {
		t.Fatalf("decrypt failed: %v", err)
	}
}

func TestDHIESV2_ForgedSenderRejected(t *testing.T) {
	alice, _ := GenerateInternal()
	bob, _ := GenerateInternal()
	mallory, _ := GenerateInternal()

	dA, _ := NewDHIES(alice)
	dB, _ := NewDHIES(bob)
	dM, _ := NewDHIES(mallory)

	// Mallory encrypts to Bob; Bob expects Alice -> must fail.
	ct, err := dM.Encrypt(bob.GetCypherPublicKey(), []byte("I am Alice"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dB.Decrypt(ct, alice.GetCypherPublicKey()); err == nil {
		t.Fatal("ciphertext from Mallory accepted as coming from Alice")
	}
	// Genuine Alice ciphertext accepted only with Alice's key.
	ct, _ = dA.Encrypt(bob.GetCypherPublicKey(), []byte("hi"))
	if _, err := dB.Decrypt(ct, mallory.GetCypherPublicKey()); err == nil {
		t.Fatal("wrong sender key accepted")
	}
	if pt, err := dB.Decrypt(ct, alice.GetCypherPublicKey()); err != nil || string(pt) != "hi" {
		t.Fatal("genuine decrypt failed")
	}
	// Wrong recipient cannot open it.
	if _, err := dM.Decrypt(ct, alice.GetCypherPublicKey()); err == nil {
		t.Fatal("non-recipient decrypted")
	}
}

func TestDHIESV2_Malformed(t *testing.T) {
	alice, _ := GenerateInternal()
	bob, _ := GenerateInternal()
	dA, _ := NewDHIES(alice)
	dB, _ := NewDHIES(bob)
	ct, _ := dA.Encrypt(bob.GetCypherPublicKey(), []byte("x"))

	bad := append([]byte{}, ct...)
	bad[0] = 0x01
	if _, err := dB.Decrypt(bad, alice.GetCypherPublicKey()); err == nil {
		t.Error("wrong version byte accepted")
	}
	for i := 0; i < len(ct); i++ {
		if _, err := dB.Decrypt(ct[:i], alice.GetCypherPublicKey()); err == nil {
			t.Errorf("truncated ciphertext (%d bytes) accepted", i)
		}
	}
	for i := 1; i < len(ct); i++ {
		tampered := append([]byte{}, ct...)
		tampered[i] ^= 0x80
		if _, err := dB.Decrypt(tampered, alice.GetCypherPublicKey()); err == nil {
			t.Errorf("tampered byte %d accepted", i)
		}
	}
	// Short / low-order keys.
	if _, err := dB.Decrypt(ct, []byte{1, 2, 3}); err == nil {
		t.Error("short sender key accepted")
	}
	if _, err := dA.Encrypt(make([]byte, 32), []byte("x")); err == nil {
		t.Error("all-zero (low-order) recipient key accepted")
	}
}

func TestDHIESV2_WorksForDilithium(t *testing.T) {
	d1, err := GenerateDilithiumInternal()
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := GenerateInternal()
	dd, err := NewDHIES(d1)
	if err != nil {
		t.Fatal(err)
	}
	de, _ := NewDHIES(e1)
	ct, err := dd.Encrypt(e1.GetCypherPublicKey(), []byte("pq"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := de.Decrypt(ct, d1.GetCypherPublicKey())
	if err != nil || string(pt) != "pq" {
		t.Fatal("dilithium sender DHIES failed")
	}
}
