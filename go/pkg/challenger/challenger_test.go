package challenger

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
	"github.com/vmihailenco/msgpack/v5"
)

func unmarshalForTest(b []byte, c *Challenge) error {
	return msgpack.Unmarshal(b, c)
}

func seq(n int, start int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(start + i)
	}
	return b
}

// TestSerializeUnsigned_MatchesTypeScript checks SerializeUnsigned against
// bytes produced by TypeScript v1 serializeUnsigned (@msgpack/msgpack
// `encode({version, protocol, service, timestamp, pk1, pk2, nonce, metadata})`).
func TestSerializeUnsigned_MatchesTypeScript(t *testing.T) {
	cases := []struct {
		name string
		ch   *Challenge
		want string
	}{
		{
			name: "metadata pk1 (insertion order) + empty pk2",
			ch: &Challenge{
				Version: 1, Protocol: "p2p", Service: "auth", Timestamp: 1700000000123,
				PK1: seq(70, 1), PK2: seq(70, 100), Nonce: seq(32, 200),
				Metadata: ChallengeMetadata{
					PK1: Metadata{{"name", "alice"}, {"a", "b"}},
					PK2: Metadata{},
				},
			},
			want: "88a776657273696f6e01a870726f746f636f6ca3703270a773657276696365a461757468a974696d657374616d70cf0000018bcfe5687ba3706b31c4460102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546a3706b32c4466465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9a56e6f6e6365c420c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7a86d6574616461746182a3706b3182a46e616d65a5616c696365a161a162a3706b3280",
		},
		{
			name: "no metadata, str8 service, bin16 pk1",
			ch: &Challenge{
				Version: 1, Protocol: "test-protocol", Service: "test-service-with-a-longer-name-over-31", Timestamp: 1700000000123,
				PK1: seq(300, 7), PK2: seq(70, 9), Nonce: seq(32, 0),
			},
			want: "88a776657273696f6e01a870726f746f636f6cad746573742d70726f746f636f6ca773657276696365d927746573742d736572766963652d776974682d612d6c6f6e6765722d6e616d652d6f7665722d3331a974696d657374616d70cf0000018bcfe5687ba3706b31c5012c0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132a3706b32c446090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4ea56e6f6e6365c420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fa86d6574616461746180",
		},
		{
			name: "metadata pk2 only",
			ch: &Challenge{
				Version: 1, Protocol: "p", Service: "s", Timestamp: 1700000000123,
				PK1: seq(70, 1), PK2: seq(70, 2), Nonce: seq(32, 3),
				Metadata: ChallengeMetadata{PK2: Metadata{{"z", "1"}}},
			},
			want: "88a776657273696f6e01a870726f746f636f6ca170a773657276696365a173a974696d657374616d70cf0000018bcfe5687ba3706b31c4460102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546a3706b32c44602030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647a56e6f6e6365c420030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122a86d6574616461746181a3706b3281a17aa131",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SerializeUnsigned(tc.ch)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != tc.want {
				t.Fatalf("unsigned bytes differ from TypeScript\n got %x\nwant %s", got, tc.want)
			}
			// Round trip through the wire format keeps metadata presence and order.
			tc.ch.Sign2 = []byte{1}
			wire, err := Serialize(tc.ch)
			if err != nil {
				t.Fatal(err)
			}
			var back Challenge
			if err := unmarshalForTest(wire, &back); err != nil {
				t.Fatal(err)
			}
			again, _ := SerializeUnsigned(&back)
			if !bytes.Equal(again, got) {
				t.Fatalf("round trip changed unsigned bytes")
			}
		})
	}
}

func TestSerializeUnsigned_RejectsVersion0(t *testing.T) {
	if _, err := SerializeUnsigned(&Challenge{Version: 0, Protocol: "p", Service: "s", Timestamp: 1}); err == nil {
		t.Fatal("version 0 must be rejected")
	}
}

type party struct {
	id *vaultysid.VaultysID
	c  *Challenger
}

func newParty(t *testing.T) party {
	t.Helper()
	id, err := vaultysid.GeneratePerson()
	if err != nil {
		t.Fatal(err)
	}
	return party{id: id, c: NewChallenger(id, nil)}
}

// handshake runs a full handshake and returns the three messages.
func handshake(t *testing.T, alice, bob party) (init, step1, complete *Challenge) {
	t.Helper()
	var err error
	init, err = alice.c.Init("p2p", "auth")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	step1, err = bob.c.Step1(init)
	if err != nil {
		t.Fatalf("step1: %v", err)
	}
	complete, err = alice.c.Step2(step1)
	if err != nil {
		t.Fatalf("step2: %v", err)
	}
	if err := bob.c.Finalize(complete); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	return
}

func TestChallenger_BasicFlow(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	alice.c.SetMetadata("name", "alice")
	bob.c.SetMetadata("name", "bob")

	_, _, complete := handshake(t, alice, bob)

	if !alice.c.IsComplete() || !bob.c.IsComplete() {
		t.Fatal("both should be complete")
	}
	if !bytes.Equal(alice.c.GetRemoteID(), bob.id.ToBytes()) {
		t.Error("Alice's remote ID should be Bob")
	}
	if !bytes.Equal(bob.c.GetRemoteID(), alice.id.ToBytes()) {
		t.Error("Bob's remote ID should be Alice")
	}
	if v, _ := complete.Metadata.PK1.Get("name"); v != "alice" {
		t.Error("metadata.pk1 missing")
	}
	if v, _ := complete.Metadata.PK2.Get("name"); v != "bob" {
		t.Error("metadata.pk2 missing")
	}

	certA, err := alice.c.GetCertificate()
	if err != nil {
		t.Fatal(err)
	}
	certB, _ := bob.c.GetCertificate()
	if !bytes.Equal(certA, certB) {
		t.Error("both parties should hold the same certificate")
	}
	if _, err := VerifyCertificate(certA); err != nil {
		t.Fatalf("certificate should verify: %v", err)
	}
	remote, err := bob.c.GetRemoteVaultysID()
	if err != nil || !bytes.Equal(remote.ToBytes(), alice.id.ToBytes()) || !remote.HasCertificate() {
		t.Fatal("GetRemoteVaultysID should return Alice with certificate")
	}
}

func TestChallenger_AcceptFullHandshake(t *testing.T) {
	alice, bob := newParty(t), newParty(t)

	init, err := alice.c.Init("protocol", "service")
	if err != nil {
		t.Fatal(err)
	}
	initBytes, _ := Serialize(init)

	step1, err := bob.c.Accept(initBytes)
	if err != nil || step1.State != StateStep1 {
		t.Fatalf("Bob Accept(init): %v", err)
	}
	step1Bytes, _ := Serialize(step1)

	complete, err := alice.c.Accept(step1Bytes)
	if err != nil || complete.State != StateComplete {
		t.Fatalf("Alice Accept(step1): %v", err)
	}
	completeBytes, _ := Serialize(complete)

	resp, err := bob.c.Accept(completeBytes)
	if err != nil || resp != nil {
		t.Fatalf("Bob Accept(complete): %v %v", resp, err)
	}
	if !bob.c.IsComplete() || !alice.c.IsComplete() {
		t.Fatal("both should be complete")
	}
}

func TestChallenger_Process(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	msg, _ := alice.c.Init("protocol", "service")
	msg, err := bob.c.Process(msg)
	if err != nil {
		t.Fatal(err)
	}
	msg, err = alice.c.Process(msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.c.Process(msg); err != nil {
		t.Fatal(err)
	}
	if !alice.c.IsComplete() || !bob.c.IsComplete() {
		t.Fatal("both should be complete")
	}
}

func expectError(t *testing.T, c *Challenger, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error", what)
	}
	if c.GetState() != StateError {
		t.Fatalf("%s: challenger should be in ERROR, got %d", what, c.GetState())
	}
}

// Finding 1: a replayed COMPLETE certificate must not authenticate anyone.
func TestChallenger_ReplayedCompleteRejected(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	_, _, complete := handshake(t, alice, bob)
	completeBytes, _ := Serialize(complete)

	// A fresh responder session (Bob again, or anyone) receiving the old COMPLETE.
	fresh := NewChallenger(bob.id, nil)
	_, err := fresh.Accept(completeBytes)
	expectError(t, fresh, err, "replayed COMPLETE via Accept")
	if fresh.GetRemoteID() != nil {
		t.Fatal("no remote id may be exposed")
	}

	fresh2 := NewChallenger(bob.id, nil)
	expectError(t, fresh2, fresh2.Finalize(complete), "replayed COMPLETE via Finalize")

	// The finished session cannot be finalized again.
	if err := bob.c.Finalize(complete); err == nil {
		t.Fatal("COMPLETE is terminal")
	}
}

// Replaying a COMPLETE into a different, live STEP1 session fails.
func TestChallenger_CompleteFromOtherSessionRejected(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	_, _, oldComplete := handshake(t, alice, bob)

	alice2 := party{alice.id, NewChallenger(alice.id, nil)}
	bob2 := party{bob.id, NewChallenger(bob.id, nil)}
	init, _ := alice2.c.Init("p2p", "auth")
	if _, err := bob2.c.Step1(init); err != nil {
		t.Fatal(err)
	}
	expectError(t, bob2.c, bob2.c.Finalize(oldComplete), "COMPLETE of another session")
}

// Finding 1 / spec: UNINITIALISED + STEP1 -> ERROR (no signing oracle).
func TestChallenger_Step1WhileUninitialisedRejected(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	init, _ := alice.c.Init("p2p", "auth")
	step1, _ := bob.c.Step1(init)
	step1Bytes, _ := Serialize(step1)

	victim := NewChallenger(alice.id, nil)
	resp, err := victim.Accept(step1Bytes)
	expectError(t, victim, err, "STEP1 while UNINITIALISED")
	if resp != nil {
		t.Fatal("must not produce a signed COMPLETE")
	}
}

func TestChallenger_Version0Rejected(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	init, _ := alice.c.Init("p2p", "auth")
	init.Version = 0
	_, err := bob.c.Step1(init)
	expectError(t, bob.c, err, "version 0 INIT")

	init.Version = 2
	bob2 := NewChallenger(bob.id, nil)
	_, err = bob2.Step1(init)
	expectError(t, bob2, err, "version 2 INIT")

	// version 0 on the wire is rejected by Deserialize as well
	init.Version = 0
	wire, _ := Serialize(init)
	if _, err := Deserialize(wire); err == nil {
		t.Fatal("Deserialize must reject version 0")
	}
}

func TestChallenger_ReflectionRejected(t *testing.T) {
	alice := newParty(t)
	init, _ := alice.c.Init("p2p", "auth")
	// Alice's own INIT reflected back to another Alice session.
	self := NewChallenger(alice.id, nil)
	_, err := self.Step1(init)
	expectError(t, self, err, "reflected INIT")

	// Initiator rejects a STEP1 whose pk2 is itself.
	step1 := init.Clone()
	step1.PK2 = alice.id.ToBytes()
	step1.Nonce = append(append([]byte{}, init.Nonce...), seq(16, 0)...)
	unsigned, _ := SerializeUnsigned(step1)
	step1.Sign2, _ = alice.id.SignHandshake(unsigned)
	step1.State = StateStep1
	_, err = alice.c.Step2(step1)
	expectError(t, alice.c, err, "reflected STEP1")
}

// Finding 2: the initiator must not sign whatever the responder sends. A
// malicious responder re-signs a STEP1 with altered fields; every
// alteration must be refused.
func TestChallenger_TamperedStep1Rejected(t *testing.T) {
	tampers := map[string]func(c *Challenge){
		"protocol":     func(c *Challenge) { c.Protocol = "other" },
		"service":      func(c *Challenge) { c.Service = "transfer" },
		"timestamp":    func(c *Challenge) { c.Timestamp-- },
		"metadata.pk1": func(c *Challenge) { c.Metadata.PK1 = Metadata{{"evil", "1"}} },
		"metadata.pk1 absent": func(c *Challenge) {
			c.Metadata.PK1 = nil
		},
		"nonce[0:16]": func(c *Challenge) { c.Nonce[0] ^= 1 },
		"pk1": func(c *Challenge) {
			other, _ := vaultysid.GeneratePerson()
			c.PK1 = other.ToBytes()
		},
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			alice, mallory := newParty(t), newParty(t)
			init, _ := alice.c.Init("p2p", "auth")
			step1, err := mallory.c.Step1(init)
			if err != nil {
				t.Fatal(err)
			}
			tamper(step1)
			// Mallory re-signs so only the semantic checks can catch it.
			unsigned, _ := SerializeUnsigned(step1)
			step1.Sign2, _ = mallory.id.SignHandshake(unsigned)
			_, err = alice.c.Step2(step1)
			expectError(t, alice.c, err, "tampered STEP1 "+name)
		})
	}

	t.Run("version", func(t *testing.T) {
		alice, mallory := newParty(t), newParty(t)
		init, _ := alice.c.Init("p2p", "auth")
		step1, _ := mallory.c.Step1(init)
		step1.Version = 0
		_, err := alice.c.Step2(step1)
		expectError(t, alice.c, err, "tampered STEP1 version")
	})

	t.Run("metadata.pk2 without re-signing", func(t *testing.T) {
		alice, bob := newParty(t), newParty(t)
		init, _ := alice.c.Init("p2p", "auth")
		step1, _ := bob.c.Step1(init)
		step1.Metadata.PK2 = Metadata{{"injected", "x"}}
		_, err := alice.c.Step2(step1)
		expectError(t, alice.c, err, "metadata.pk2 tampered in transit")
	})
}

func TestChallenger_TamperedCompleteRejected(t *testing.T) {
	tampers := map[string]func(c *Challenge){
		"protocol":     func(c *Challenge) { c.Protocol = "other" },
		"service":      func(c *Challenge) { c.Service = "other" },
		"timestamp":    func(c *Challenge) { c.Timestamp++ },
		"version":      func(c *Challenge) { c.Version = 0 },
		"nonce":        func(c *Challenge) { c.Nonce[31] ^= 1 },
		"metadata.pk1": func(c *Challenge) { c.Metadata.PK1 = Metadata{{"k", "v"}} },
		"metadata.pk2": func(c *Challenge) { c.Metadata.PK2 = Metadata{{"k", "v"}} },
		"sign2":        func(c *Challenge) { c.Sign2 = append([]byte{}, c.Sign2...); c.Sign2[0] ^= 1 },
		"sign1":        func(c *Challenge) { c.Sign1[0] ^= 1 },
		"pk2": func(c *Challenge) {
			other, _ := vaultysid.GeneratePerson()
			c.PK2 = other.ToBytes()
		},
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			alice, bob := newParty(t), newParty(t)
			init, _ := alice.c.Init("p2p", "auth")
			step1, _ := bob.c.Step1(init)
			complete, err := alice.c.Step2(step1)
			if err != nil {
				t.Fatal(err)
			}
			tamper(complete)
			// Alice (who holds the key) re-signs: field equality must still catch it.
			if name != "sign1" && complete.Version == 1 {
				unsigned, _ := SerializeUnsigned(complete)
				complete.Sign1, _ = alice.id.SignHandshake(unsigned)
			}
			expectError(t, bob.c, bob.c.Finalize(complete), "tampered COMPLETE "+name)
		})
	}
}

func TestChallenger_TerminalStates(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	init, step1, _ := handshake(t, alice, bob)

	if _, err := alice.c.Init("p", "s"); err == nil {
		t.Error("Init after COMPLETE must fail")
	}
	if _, err := bob.c.Step1(init); err == nil {
		t.Error("Step1 after COMPLETE must fail")
	}
	if _, err := alice.c.Step2(step1); err == nil {
		t.Error("Step2 after COMPLETE must fail")
	}

	// ERROR is terminal too.
	c := NewChallenger(alice.id, nil)
	_, _ = c.Step2(step1) // UNINITIALISED + STEP1 -> ERROR
	if _, err := c.Init("p", "s"); err == nil || c.GetState() != StateError {
		t.Error("ERROR must be terminal")
	}
}

func TestChallenger_TimestampWindow(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	init, _ := alice.c.Init("p2p", "auth")
	init.Timestamp = uint64(crypto.Now() - 2*time.Minute.Milliseconds())
	_, err := bob.c.Step1(init)
	expectError(t, bob.c, err, "stale INIT")

	init.Timestamp = uint64(crypto.Now() + 2*time.Minute.Milliseconds())
	bob2 := NewChallenger(bob.id, nil)
	_, err = bob2.Step1(init)
	expectError(t, bob2, err, "future INIT")
}

func TestChallenger_InitStructure(t *testing.T) {
	alice := newParty(t)
	init, _ := alice.c.Init("p2p", "auth")
	bad := []func(c *Challenge){
		func(c *Challenge) { c.Nonce = c.Nonce[:15] },
		func(c *Challenge) { c.PK1 = []byte{0x01, 0x02} },
		func(c *Challenge) { c.PK1 = nil },
		func(c *Challenge) { c.Metadata.PK2 = Metadata{} },
		func(c *Challenge) { c.Service = "" },
	}
	for i, mutate := range bad {
		ch := init.Clone()
		mutate(ch)
		b := newParty(t)
		_, err := b.c.Step1(ch)
		if err == nil {
			t.Errorf("case %d: malformed INIT accepted", i)
		}
	}
}

func TestChallenger_AcceptCallbackGetsRemote(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	var seenByBob, seenByAlice []byte
	bob.c = NewChallenger(bob.id, &ChallengerOptions{Accept: func(r *vaultysid.VaultysID, p, s string) error {
		seenByBob = r.ToBytes()
		return nil
	}})
	alice.c = NewChallenger(alice.id, &ChallengerOptions{Accept: func(r *vaultysid.VaultysID, p, s string) error {
		seenByAlice = r.ToBytes()
		return nil
	}})
	handshake(t, alice, bob)
	if !bytes.Equal(seenByBob, alice.id.ToBytes()) || !bytes.Equal(seenByAlice, bob.id.ToBytes()) {
		t.Fatal("accept callbacks must receive the remote identity")
	}

	carol := party{bob.id, NewChallenger(bob.id, &ChallengerOptions{Accept: func(*vaultysid.VaultysID, string, string) error {
		return errors.New("no")
	}})}
	a2 := newParty(t)
	init, _ := a2.c.Init("p2p", "auth")
	_, err := carol.c.Step1(init)
	expectError(t, carol.c, err, "refused")
}

func TestChallenger_GetRemoteBeforeComplete(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	init, _ := alice.c.Init("p2p", "auth")
	if _, err := bob.c.Step1(init); err != nil {
		t.Fatal(err)
	}
	if bob.c.GetRemoteID() != nil {
		t.Error("remote id must not be exposed before COMPLETE")
	}
	if _, err := bob.c.GetRemoteVaultysID(); err == nil {
		t.Error("remote must not be exposed before COMPLETE")
	}
	if _, err := bob.c.GetCertificate(); err == nil {
		t.Error("certificate must not be available before COMPLETE")
	}
}

// Handshake signatures are domain-separated from every public signing API.
func TestChallenger_DomainSeparation(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	_, _, complete := handshake(t, alice, bob)
	unsigned, _ := SerializeUnsigned(complete)

	if alice.id.VerifyChallenge(unsigned, complete.Sign1) == nil {
		t.Error("handshake signature must not verify as VAULTYS_SIGN")
	}
	if alice.id.Verify(unsigned, complete.Sign1) == nil {
		t.Error("handshake signature must not verify as VAULTYS_RAW")
	}
	// Signatures from the public APIs cannot complete a handshake.
	forged := complete.Clone()
	forged.Sign1, _ = alice.id.SignChallenge(unsigned)
	if forged.Sign1 != nil && alice.id.VerifyHandshake(unsigned, forged.Sign1) == nil {
		t.Error("VAULTYS_SIGN signature accepted as handshake")
	}
	forged.Sign1, _ = alice.id.Sign(unsigned)
	if alice.id.VerifyHandshake(unsigned, forged.Sign1) == nil {
		t.Error("VAULTYS_RAW signature accepted as handshake")
	}
}

func TestVerifyCertificate_ReadOnlyPublicOnly(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	handshake(t, alice, bob)
	cert, _ := alice.c.GetCertificate()

	ch, err := VerifyCertificate(cert)
	if err != nil || ch.State != StateComplete {
		t.Fatalf("certificate should verify: %v", err)
	}
	// Uses only public ids.
	if _, err := vaultysid.FromID(ch.PK1, nil); err != nil {
		t.Fatal(err)
	}

	bad := append([]byte{}, cert...)
	bad[len(bad)/2] ^= 0xff
	if _, err := VerifyCertificate(bad); err == nil {
		t.Fatal("corrupted certificate accepted")
	}
	init, _ := NewChallenger(alice.id, nil).Init("p", "s")
	initBytes, _ := Serialize(init)
	if _, err := VerifyCertificate(initBytes); err == nil {
		t.Fatal("INIT is not a certificate")
	}
}

func TestDeserialize_GarbageNoPanic(t *testing.T) {
	alice, bob := newParty(t), newParty(t)
	_, _, complete := handshake(t, alice, bob)
	wire, _ := Serialize(complete)

	inputs := [][]byte{nil, {}, []byte("invalid"), {0x80}, {0xc0}, {0x81, 0xa8}, {0xde, 0xff, 0xff}}
	for i := 0; i < len(wire); i += 7 {
		inputs = append(inputs, wire[:i])
	}
	for i := 0; i < len(wire); i += 11 {
		m := append([]byte{}, wire...)
		m[i] ^= 0xff
		inputs = append(inputs, m)
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %x: %v", in, r)
				}
			}()
			_, _ = Deserialize(in)
			c := NewChallenger(bob.id, nil)
			_, _ = c.Accept(in)
		}()
	}

	serialized, _ := Serialize(&Challenge{Version: ProtocolV1, State: StateInit})
	d, err := Deserialize(serialized)
	if err == nil || d.State != StateError {
		t.Error("missing fields must be an error")
	}
}

func TestChallenge_Clone(t *testing.T) {
	original := &Challenge{
		Version: ProtocolV1, Protocol: "test", Service: "service", Timestamp: 12345,
		PK1: []byte{1, 2, 3}, PK2: []byte{4, 5, 6}, Nonce: []byte{7, 8, 9},
		Sign1: []byte{10, 11, 12}, Sign2: []byte{13, 14, 15},
		State: StateComplete, Error: "test error",
		Metadata: ChallengeMetadata{
			PK1: NewMetadata(map[string]string{"key1": "value1"}),
			PK2: Metadata{},
		},
	}
	clone := original.Clone()
	if v, _ := clone.Metadata.PK1.Get("key1"); v != "value1" || clone.Metadata.PK2 == nil {
		t.Error("metadata not cloned correctly")
	}
	clone.PK1[0] = 99
	clone.Metadata.PK1[0].Value = "x"
	if original.PK1[0] == 99 || original.Metadata.PK1[0].Value == "x" {
		t.Error("modifying clone affected original")
	}
}

func TestChallenger_ResetAndMetadata(t *testing.T) {
	alice := newParty(t)
	alice.c.SetMetadata("k", "v")
	if v, ok := alice.c.GetMetadata("k"); !ok || v != "v" {
		t.Fatal("metadata get/set")
	}
	if _, err := alice.c.Init("p", "s"); err != nil {
		t.Fatal(err)
	}
	alice.c.Reset()
	if alice.c.GetState() != StateUninitialized {
		t.Fatal("reset")
	}
	if _, err := alice.c.Init("p2", "s2"); err != nil {
		t.Fatal(err)
	}
}
