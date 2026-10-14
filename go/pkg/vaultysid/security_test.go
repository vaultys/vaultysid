package vaultysid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/vaultys/vaultysid/go/pkg/keymanager"
	"github.com/vmihailenco/msgpack/v5"
)

// Spec §2: raw Sign, SignChallenge and SignHandshake are domain-separated.
func TestDomainSeparation(t *testing.T) {
	vid, _ := GeneratePerson()
	data := []byte("some bytes")

	raw, _ := vid.Sign(data)
	chal, _ := vid.SignChallenge(data)
	hs, _ := vid.SignHandshake(data)

	if vid.Verify(data, raw) != nil || vid.VerifyChallenge(data, chal) != nil || vid.VerifyHandshake(data, hs) != nil {
		t.Fatal("each signature must verify under its own API")
	}
	cross := []struct {
		name string
		err  error
	}{
		{"raw as handshake", vid.VerifyHandshake(data, raw)},
		{"raw as challenge", vid.VerifyChallenge(data, raw)},
		{"challenge as handshake", vid.VerifyHandshake(data, chal)},
		{"challenge as raw", vid.Verify(data, chal)},
		{"handshake as raw", vid.Verify(data, hs)},
		{"handshake as challenge", vid.VerifyChallenge(data, hs)},
	}
	for _, c := range cross {
		if c.err == nil {
			t.Errorf("%s must not verify", c.name)
		}
	}

	// Sign is not raw: the key manager signature over data itself differs
	// and a raw key-manager signature over SHA-256("VAULTYS_HANDSHAKE_V1"||x)
	// can't be obtained through Sign.
	h := sha256.Sum256(append([]byte("VAULTYS_RAW"), data...))
	if vid.KeyManager.Verify(h[:], raw) != nil {
		t.Fatal("Sign must be over SHA-256(\"VAULTYS_RAW\" || data)")
	}
	if vid.KeyManager.Verify(data, raw) == nil {
		t.Fatal("Sign must not be raw")
	}
}

// Finding 11: VerifyDIDDocument must compare the advertised keys.
func TestVerifyDIDDocument_ChecksKeys(t *testing.T) {
	vid, _ := GeneratePerson()
	other, _ := GeneratePerson()

	if err := vid.VerifyDIDDocument(vid.DIDDocument()); err != nil {
		t.Fatalf("own document rejected: %v", err)
	}

	doc := vid.DIDDocument()
	doc.Authentication[0].PublicKeyMultibase = other.DIDDocument().Authentication[0].PublicKeyMultibase
	if vid.VerifyDIDDocument(doc) == nil {
		t.Error("foreign authentication key accepted")
	}

	doc = vid.DIDDocument()
	doc.KeyAgreement[0].PublicKeyMultibase = other.DIDDocument().KeyAgreement[0].PublicKeyMultibase
	if vid.VerifyDIDDocument(doc) == nil {
		t.Error("foreign key agreement key accepted")
	}

	doc = vid.DIDDocument()
	doc.KeyAgreement[0].PublicKeyMultibase = "u" + base64.RawURLEncoding.EncodeToString([]byte("x"))
	if vid.VerifyDIDDocument(doc) == nil {
		t.Error("garbage key accepted")
	}
	doc.KeyAgreement[0].PublicKeyMultibase = "u!!"
	if vid.VerifyDIDDocument(doc) == nil {
		t.Error("undecodable key accepted")
	}
}

func fido2TestID(t *testing.T) []byte {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(nil)
	ckey, err := cbor.Marshal(map[int]interface{}{1: 1, 3: -8, -1: 6, -2: []byte(pub)})
	if err != nil {
		t.Fatal(err)
	}
	km, err := msgpack.Marshal(map[string]interface{}{"v": 1, "c": ckey, "e": bytes.Repeat([]byte{9}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{byte(TypeFIDO2)}, km...)
}

// mutations returns truncations, bit flips and garbage derived from b.
func mutations(b []byte) [][]byte {
	out := [][]byte{nil, {}, {0x00}, {0x01}, {0x03}, {0x04}, {0xff}, []byte("garbage")}
	for i := 0; i <= len(b); i++ {
		if len(b) > 400 && i%37 != 0 && i < len(b)-4 {
			continue
		}
		out = append(out, b[:i])
	}
	for i := 0; i < len(b); i++ {
		if len(b) > 400 && i%41 != 0 {
			continue
		}
		for _, x := range []byte{0x01, 0x80, 0xff} {
			m := append([]byte{}, b...)
			m[i] ^= x
			out = append(out, m)
		}
	}
	return out
}

func encodeKM(t *testing.T, typ IdentityType, v interface{}) []byte {
	t.Helper()
	b, err := msgpack.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{byte(typ)}, b...)
}

// Finding 3: no parser of untrusted ids/secrets may panic, and malformed
// key lengths must be rejected up front.
func TestParsers_NoPanicOnMalformedInput(t *testing.T) {
	ed, _ := GeneratePerson()
	dil, err := GeneratePersonAlg("dilithium")
	if err != nil {
		t.Fatal(err)
	}
	edSecret, _ := ed.GetSecret()
	dilSecret, _ := dil.GetSecret()

	if _, err := FromID(fido2TestID(t), nil); err != nil {
		t.Fatalf("fido2 seed id must parse: %v", err)
	}

	var inputs [][]byte
	for _, seed := range [][]byte{ed.ToBytes(), dil.ToBytes(), edSecret, dilSecret, fido2TestID(t)} {
		inputs = append(inputs, mutations(seed)...)
	}
	// Hand-crafted short keys (the original remote DoS).
	short := [][]byte{
		encodeKM(t, TypePerson, map[string]interface{}{"v": 1, "x": []byte{1, 2, 3}, "e": bytes.Repeat([]byte{1}, 32)}),
		encodeKM(t, TypePerson, map[string]interface{}{"v": 1, "x": bytes.Repeat([]byte{1}, 32), "e": []byte{1}}),
		encodeKM(t, TypePerson, map[string]interface{}{"v": 1}),
		encodeKM(t, TypePerson, map[string]interface{}{"v": 1, "x": "str", "e": 5}),
		encodeKM(t, TypePerson, map[string]interface{}{"v": 7, "x": bytes.Repeat([]byte{1}, 32), "e": bytes.Repeat([]byte{1}, 32)}),
		encodeKM(t, TypeFIDO2, map[string]interface{}{"v": 1, "c": []byte{0xa0}, "e": bytes.Repeat([]byte{1}, 32)}),
		encodeKM(t, TypeFIDO2, map[string]interface{}{"v": 1, "f": []byte{1}, "c": []byte{0xff, 0xff}, "e": []byte{1}}),
	}
	inputs = append(inputs, short...)

	msg := []byte("m")
	sig := bytes.Repeat([]byte{7}, 64)
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on input %x: %v", in, r)
				}
			}()
			if v, err := FromID(in, nil); err == nil {
				_ = v.Verify(msg, sig)
				_ = v.VerifyChallenge(msg, sig)
				_ = v.VerifyHandshake(msg, sig)
				_ = v.Verify(msg, nil)
				_ = v.DID()
				_ = v.DIDDocument()
			}
			if v, err := FromSecret(in); err == nil {
				_, _ = v.Sign(msg)
				_ = v.Verify(msg, sig)
				_, _ = v.HMAC("x")
				_, _ = v.DHIESEncrypt(msg, ed)
			}
		}()
	}
	for i, in := range short[:5] {
		if _, err := FromID(in, nil); err == nil {
			t.Errorf("short-key id %d accepted", i)
		}
		if _, err := FromSecret(in); err == nil {
			t.Errorf("short-key secret %d accepted", i)
		}
	}
}

// Even a hand-built key manager with a bad key must not panic in Verify.
func TestEd25519Verify_ShortKeyNoPanic(t *testing.T) {
	km := &keymanager.Ed25519Manager{Version: 1, Capability: "public", Signer: keymanager.KeyPair{PublicKey: []byte{1, 2, 3}}}
	if km.Verify([]byte("x"), make([]byte, 64)) == nil {
		t.Fatal("short key must not verify")
	}
	km2 := &keymanager.Ed25519Manager{Version: 1, Capability: "private", Signer: keymanager.KeyPair{SecretKey: []byte{1}}}
	if _, err := km2.Sign([]byte("x")); err == nil {
		t.Fatal("short secret must not sign")
	}
}

func TestDHIES_V2ThroughVaultysID(t *testing.T) {
	alice, _ := GeneratePerson()
	bob, _ := GeneratePerson()
	mallory, _ := GeneratePerson()
	ct, err := alice.DHIESEncrypt([]byte("hello"), bob)
	if err != nil {
		t.Fatal(err)
	}
	if ct[0] != keymanager.DHIESV2Version {
		t.Fatal("expected DHIES v2 header")
	}
	if pt, err := bob.DHIESDecrypt(ct, alice); err != nil || string(pt) != "hello" {
		t.Fatalf("decrypt: %v", err)
	}
	if _, err := bob.DHIESDecrypt(ct, mallory); err == nil {
		t.Fatal("forged sender accepted")
	}
	forged, _ := mallory.DHIESEncrypt([]byte("hello"), bob)
	if _, err := bob.DHIESDecrypt(forged, alice); err == nil {
		t.Fatal("mallory's ciphertext accepted as alice's")
	}
}
