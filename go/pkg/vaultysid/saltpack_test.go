package vaultysid

import (
	"errors"
	"strings"
	"testing"
)

func mustIdentity(t *testing.T, alg string) *VaultysID {
	t.Helper()
	id, err := GeneratePersonAlg(alg)
	if err != nil {
		t.Fatalf("generate %s: %v", alg, err)
	}
	return id
}

func TestSaltpackRoundTrip(t *testing.T) {
	for _, alg := range []string{"ed25519", "dilithium"} {
		t.Run(alg, func(t *testing.T) {
			alice, bob, carol := mustIdentity(t, alg), mustIdentity(t, "ed25519"), mustIdentity(t, "dilithium")

			ct, err := Encrypt("hello", []*VaultysID{bob, carol})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(ct, "BEGIN SALTPACK ENCRYPTED MESSAGE.") {
				t.Fatalf("unexpected armor: %.40s", ct)
			}
			for _, r := range []*VaultysID{bob, carol} {
				if got, err := r.Decrypt(ct); err != nil || got != "hello" {
					t.Fatalf("decrypt: %q %v", got, err)
				}
			}
			if _, err := alice.Decrypt(ct); err == nil {
				t.Fatal("a non-recipient decrypted the message")
			}
			// Anonymous: no sender can be claimed.
			if _, err := bob.DecryptFrom(ct, alice); !errors.Is(err, ErrUnexpectedSender) {
				t.Fatalf("anonymous message accepted as from alice: %v", err)
			}

			signed, err := alice.Signcrypt("from alice", []*VaultysID{bob})
			if err != nil {
				t.Fatal(err)
			}
			if got, err := bob.DecryptFrom(signed, alice); err != nil || got != "from alice" {
				t.Fatalf("DecryptFrom: %q %v", got, err)
			}
			if _, err := bob.DecryptFrom(signed, carol); !errors.Is(err, ErrUnexpectedSender) {
				t.Fatalf("message from alice accepted as from carol: %v", err)
			}
		})
	}
}

func TestSaltpackTamperedCiphertextFails(t *testing.T) {
	bob := mustIdentity(t, "ed25519")
	ct, err := Encrypt("integrity", []*VaultysID{bob})
	if err != nil {
		t.Fatal(err)
	}
	// Flip one Base62 character in the body.
	body := strings.Index(ct, ". ") + 6
	flipped := []byte(ct)
	if flipped[body] == 'a' {
		flipped[body] = 'b'
	} else {
		flipped[body] = 'a'
	}
	if _, err := bob.Decrypt(string(flipped)); err == nil {
		t.Fatal("a tampered message decrypted")
	}
}

func TestSaltpackPublicIdentityCannotDecrypt(t *testing.T) {
	bob := mustIdentity(t, "ed25519")
	ct, err := Encrypt("x", []*VaultysID{bob})
	if err != nil {
		t.Fatal(err)
	}
	public, err := FromID(bob.ID(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := public.Decrypt(ct); err == nil {
		t.Fatal("a public-only identity decrypted the message")
	}
	if _, err := public.Signcrypt("x", []*VaultysID{bob}); err == nil {
		t.Fatal("a public-only identity signcrypted")
	}
	// But anyone can encrypt *to* a public identity.
	if _, err := Encrypt("x", []*VaultysID{public}); err != nil {
		t.Fatalf("encrypt to public identity: %v", err)
	}
}
