package challenger

import (
	"bytes"
	"testing"

	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

// rfc/PQ-ENCRYPTION.md §6: the handshake is algorithm-agnostic, PQ identities
// simply appear in pk1 / pk2.
func TestChallenger_PostQuantumIdentities(t *testing.T) {
	newIdentity := func(idType vaultysid.IdentityType, alg string) party {
		entropy, _ := crypto.RandomBytes(32)
		id, err := vaultysid.FromEntropyAlg(entropy, idType, alg)
		if err != nil {
			t.Fatal(err)
		}
		return party{id: id, c: NewChallenger(id, nil)}
	}
	pairs := [][2]party{
		{newIdentity(vaultysid.TypePQPerson, "dilithium_ed25519"), newIdentity(vaultysid.TypePQMachine, "dilithium")},
		{newIdentity(vaultysid.TypePerson, "ed25519"), newIdentity(vaultysid.TypePQOrganization, "dilithium_ed25519")},
	}
	for _, p := range pairs {
		alice, bob := p[0], p[1]
		_, _, _ = handshake(t, alice, bob)
		cert, err := alice.c.GetCertificate()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyCertificate(cert); err != nil {
			t.Fatalf("certificate: %v", err)
		}
		remote, err := alice.c.GetRemoteVaultysID()
		if err != nil || !bytes.Equal(remote.ToBytes(), bob.id.ToBytes()) {
			t.Fatal("remote id")
		}
		if remote.IsPostQuantum() != bob.id.IsPostQuantum() || remote.IsMachine() != bob.id.IsMachine() {
			t.Error("remote type or role")
		}
		if bob.id.IsPostQuantum() && !bytes.Equal(remote.GetKEMPublicKey(), bob.id.GetKEMPublicKey()) {
			t.Error("remote ML-KEM key lost")
		}
	}
}
