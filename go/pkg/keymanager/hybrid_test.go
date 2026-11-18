package keymanager

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func TestHybridManagerRoundTrip(t *testing.T) {
	km, err := GenerateHybrid()
	if err != nil {
		t.Fatal(err)
	}
	if len(km.GetPublicKey()) != HybridPublicKeySize || len(km.ToBytes()) != 2669 {
		t.Fatalf("lengths: pk %d, id %d", len(km.GetPublicKey()), len(km.ToBytes()))
	}
	secret, err := km.GetSecret()
	if err != nil || len(secret) != 83 {
		t.Fatalf("secret: %v (%d bytes)", err, len(secret))
	}
	restored, err := HybridFromSecret(secret)
	if err != nil || !bytes.Equal(restored.ToBytes(), km.ToBytes()) {
		t.Fatalf("HybridFromSecret: %v", err)
	}
	public, err := HybridFromID(km.ToBytes())
	if err != nil || public.GetCapability() != "public" {
		t.Fatalf("HybridFromID: %v", err)
	}

	sig, err := km.Sign([]byte("data"))
	if err != nil || len(sig) != 64+4627 {
		t.Fatalf("Sign: %v (%d bytes)", err, len(sig))
	}
	if err := public.Verify([]byte("data"), sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if public.Verify([]byte("other"), sig) == nil {
		t.Error("signature verified on other data")
	}
	for _, pos := range []int{0, 63, 64, len(sig) - 1} {
		tampered := append([]byte(nil), sig...)
		tampered[pos] ^= 1
		if public.Verify([]byte("data"), tampered) == nil {
			t.Errorf("tampered byte %d accepted", pos)
		}
	}
	if public.Verify([]byte("data"), sig[:64]) == nil {
		t.Error("Ed25519 half alone accepted")
	}
	if _, err := public.Sign([]byte("x")); err == nil {
		t.Error("public key manager signed")
	}
}

func TestHybridManagerRejectsMalformedInput(t *testing.T) {
	km, _ := GenerateHybrid()
	dilithium, _ := GenerateDilithiumInternal()
	if _, err := HybridFromID(dilithium.ToBytes()); err == nil {
		t.Error("Dilithium id accepted as hybrid")
	}
	dsecret, _ := dilithium.GetSecret()
	if _, err := HybridFromSecret(dsecret); err == nil {
		t.Error("secret without alg=hybrid accepted")
	}
	bad, _ := msgpack.Marshal(hybridSecretExport{V: 1, Alg: "hybrid", S: make([]byte, 32)})
	if _, err := HybridFromSecret(bad); err == nil {
		t.Error("32-byte seed accepted")
	}
	if _, err := PostQuantumFromID(km.ToBytes()); err == nil {
		t.Error("classical hybrid id accepted as post-quantum")
	}
}

// TestHybridClassicalMatchesVectors: the classical hybrid identity of a vector
// seed has the same signing and encryption keys as its post-quantum version.
func TestHybridClassicalMatchesVectors(t *testing.T) {
	v := loadPQVectors(t)
	for name, ident := range v.Identities {
		if ident.Algorithm != "dilithium_ed25519" {
			continue
		}
		secret, _ := msgpack.Marshal(hybridSecretExport{V: 1, Alg: "hybrid", S: unhex(t, ident.Seed)})
		km, err := HybridFromSecret(secret)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(km.Cypher.PublicKey) != ident.CypherPublicKey {
			t.Errorf("%s: X25519 key mismatch", name)
		}
		if km.IsPostQuantum() || !bytes.Equal(secret, unhex(t, ident.Secret)[1:]) {
			t.Errorf("%s: secret record", name)
		}
		if err := km.EnablePostQuantum(); err != nil || hex.EncodeToString(km.GetKEMPublicKey()) != ident.EK {
			t.Errorf("%s: ML-KEM key", name)
		}
	}
}
