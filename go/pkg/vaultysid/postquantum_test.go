package vaultysid

import (
	"bytes"
	"testing"

	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"github.com/vaultys/vaultysid/go/pkg/keymanager"
)

// rfc/PQ-ENCRYPTION.md: post-quantum identity types, ML-KEM key, PRF key, DHIES v3.

func newPQ(t *testing.T, idType IdentityType) *VaultysID {
	t.Helper()
	entropy, _ := crypto.RandomBytes(32)
	id, err := FromEntropyAlg(entropy, idType, "dilithium")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPQTypesAndRoles(t *testing.T) {
	machine := newPQ(t, TypePQMachine)
	person := newPQ(t, TypePQPerson)
	organization := newPQ(t, TypePQOrganization)
	if machine.ToBytes()[0] != 0x10 || person.ToBytes()[0] != 0x11 || organization.ToBytes()[0] != 0x12 {
		t.Fatal("type bytes")
	}
	if !machine.IsMachine() || machine.IsPerson() || machine.IsHardware() || !person.IsPerson() || !organization.IsOrganization() {
		t.Error("role checks must ignore the post-quantum flag")
	}
	if !machine.IsPostQuantum() || machine.GetType() != "pq-machine" {
		t.Error("IsPostQuantum / GetType")
	}
	classical, _ := GeneratePersonAlg("dilithium")
	if classical.IsPostQuantum() || classical.GetKEMPublicKey() != nil {
		t.Error("classical Dilithium identity reported as post-quantum")
	}
	if len(person.ToBytes()) != 3827 {
		t.Errorf("serialized length %d, want 3827", len(person.ToBytes()))
	}
}

func TestPQRefusesEd25519AndReservedTypes(t *testing.T) {
	entropy, _ := crypto.RandomBytes(32)
	if _, err := FromEntropyAlg(entropy, TypePQPerson, "ed25519"); err == nil {
		t.Error("Ed25519 post-quantum identity created")
	}
	pq := newPQ(t, TypePQPerson)
	for _, reserved := range []byte{0x13, 0x14, 0x15, 0x20} {
		id := append([]byte{reserved}, pq.ToBytes()[1:]...)
		if _, err := FromID(id, nil); err == nil {
			t.Errorf("type 0x%02x accepted", reserved)
		}
	}
}

func TestPQSecretRoundTripAndVersion(t *testing.T) {
	pq := newPQ(t, TypePQOrganization)
	secret, err := pq.GetSecret()
	if err != nil || len(secret) != 73 {
		t.Fatalf("secret: %v (%d bytes)", err, len(secret))
	}
	restored, err := FromSecret(secret)
	if err != nil || !bytes.Equal(restored.ToBytes(), pq.ToBytes()) || restored.DID() != pq.DID() {
		t.Fatalf("FromSecret round trip: %v", err)
	}
	did := pq.DID()
	if err := pq.ToVersion(0); err != nil || pq.GetVersion() != 1 || pq.DID() != did {
		t.Error("ToVersion(0) must leave a post-quantum identity at version 1")
	}
	// same seed, classical type: a different DID and a different PRF key
	classical, err := FromSecret(append([]byte{byte(TypePerson)}, secret[1:]...))
	if err != nil {
		t.Fatal(err)
	}
	if classical.DID()[12:] == pq.DID()[12:] {
		t.Error("PQ and classical identities share a fingerprint")
	}
	h1, _ := classical.HMAC("file")
	h2, _ := pq.HMAC("file")
	if bytes.Equal(h1, h2) {
		t.Error("post-quantum PRF keyed with the X25519 secret")
	}
}

func TestPQDIDDocumentListsKEMKey(t *testing.T) {
	pq := newPQ(t, TypePQPerson)
	doc := pq.DIDDocument()
	if len(doc.KeyAgreement) != 2 || doc.KeyAgreement[1].Type != "MLKEM768KeyAgreementKey2025" {
		t.Fatalf("key agreement: %+v", doc.KeyAgreement)
	}
	classical, _ := GeneratePerson()
	if len(classical.DIDDocument().KeyAgreement) != 1 {
		t.Error("classical DID document lists an ML-KEM key")
	}
}

func TestPQDHIESVersionSelection(t *testing.T) {
	pq := newPQ(t, TypePQPerson)
	otherPQ := newPQ(t, TypePQMachine)
	classical, _ := GeneratePerson()
	msg := []byte("hello")

	cases := []struct {
		name              string
		sender, recipient *VaultysID
		version           byte
	}{
		{"classical to PQ", classical, pq, 0x03},
		{"PQ to PQ", otherPQ, pq, 0x03},
		{"PQ to classical", pq, classical, 0x02},
	}
	for _, c := range cases {
		recipientPublic, _ := FromID(c.recipient.ToBytes(), nil)
		out, err := c.sender.DHIESEncrypt(msg, recipientPublic)
		if err != nil || out[0] != c.version {
			t.Fatalf("%s: %v", c.name, err)
		}
		got, err := c.recipient.DHIESDecrypt(out, c.sender)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("%s: decrypt: %v", c.name, err)
		}
	}
}

func TestPQRecipientRejectsDHIESV2(t *testing.T) {
	pq := newPQ(t, TypePQPerson)
	classical, _ := GeneratePerson()
	sk, _ := classical.cypherSecret()
	// a valid v2 message to the PQ identity's X25519 key
	v2, err := keymanager.DHIESEncryptV2(sk, classical.GetCypherPublicKey(), pq.GetCypherPublicKey(), []byte("downgrade"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pq.DHIESDecrypt(v2, classical); err == nil {
		t.Fatal("a post-quantum identity accepted DHIES v2")
	}
	// the same key under a classical type opens it: the refusal is the policy of §5.4
	secret, _ := pq.GetSecret()
	sameKeyClassical, _ := FromSecret(append([]byte{byte(TypePerson)}, secret[1:]...))
	if got, err := sameKeyClassical.DHIESDecrypt(v2, classical); err != nil || string(got) != "downgrade" {
		t.Fatalf("control: %v", err)
	}
	// and a classical identity refuses v3
	v3, _ := classical.DHIESEncrypt([]byte("x"), pq)
	if _, err := sameKeyClassical.DHIESDecrypt(v3, classical); err == nil {
		t.Error("a classical identity accepted DHIES v3")
	}
}

func TestPQPublicIdentityCannotDecrypt(t *testing.T) {
	pq := newPQ(t, TypePQPerson)
	classical, _ := GeneratePerson()
	out, _ := classical.DHIESEncrypt([]byte("x"), pq)
	public, _ := FromID(pq.ToBytes(), nil)
	if _, err := public.DHIESDecrypt(out, classical); err == nil {
		t.Error("public identity decrypted")
	}
	if _, err := public.GetSecretHash([]byte("x")); err == nil {
		t.Error("public identity computed getSecretHash")
	}
}

func TestHybridIdentities(t *testing.T) {
	entropy, _ := crypto.RandomBytes(32)
	for _, idType := range []IdentityType{TypePerson, TypePQPerson} {
		id, err := FromEntropyAlg(entropy, idType, "dilithium_ed25519")
		if err != nil {
			t.Fatal(err)
		}
		want := map[IdentityType]int{TypePerson: 2670, TypePQPerson: 3859}[idType]
		if len(id.ToBytes()) != want {
			t.Errorf("type %d: serialized length %d, want %d", idType, len(id.ToBytes()), want)
		}
		secret, _ := id.GetSecret()
		restored, err := FromSecret(secret)
		if err != nil || !bytes.Equal(restored.ToBytes(), id.ToBytes()) {
			t.Fatalf("type %d: FromSecret: %v", idType, err)
		}
		public, err := FromID(id.ToBytes(), nil)
		if err != nil || public.KeyManager.GetAuthType() != "DilithiumEdDSAVerificationKey2025" {
			t.Fatalf("type %d: FromID: %v", idType, err)
		}
		sig, _ := id.SignChallenge([]byte("challenge"))
		if err := public.VerifyChallenge([]byte("challenge"), sig); err != nil {
			t.Errorf("type %d: %v", idType, err)
		}
	}
	// a hybrid PQ identity receives DHIES v3
	pq, _ := FromEntropyAlg(entropy, TypePQOrganization, "dilithium_ed25519")
	classical, _ := GeneratePerson()
	out, err := classical.DHIESEncrypt([]byte("m"), pq)
	if err != nil || out[0] != 0x03 {
		t.Fatalf("DHIES v3 to hybrid: %v", err)
	}
	if got, err := pq.DHIESDecrypt(out, classical); err != nil || string(got) != "m" {
		t.Fatalf("decrypt: %v", err)
	}
}
