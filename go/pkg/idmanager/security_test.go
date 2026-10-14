package idmanager

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vaultys/vaultysid/go/pkg/challenger"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

func newTestManager(t *testing.T) (*Manager, *vaultysid.VaultysID) {
	t.Helper()
	id, err := vaultysid.GeneratePerson()
	if err != nil {
		t.Fatal(err)
	}
	return NewManager(id, NewMemoryStore()), id
}

// Finding 10: VerifyFile must fail closed unless the signed challenge commits
// to exactly this file's hash.
func TestVerifyFile_FailsClosed(t *testing.T) {
	m, id := newTestManager(t)
	file := &File{Name: "a.txt", ArrayBuffer: []byte("hello")}
	other := &File{Name: "b.txt", ArrayBuffer: []byte("evil")}

	sig, err := m.SignFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyFile(file, sig, id, false); err != nil {
		t.Fatalf("genuine signature rejected: %v", err)
	}
	if err := m.VerifyFile(other, sig, id, false); err == nil {
		t.Fatal("signature accepted for a different file")
	}

	h := sha256.Sum256(other.ArrayBuffer)
	good := hex.EncodeToString(h[:])
	signed := func(challenge string) *FileSignature {
		s, err := id.SignChallenge([]byte(challenge))
		if err != nil {
			t.Fatal(err)
		}
		return &FileSignature{Challenge: []byte(challenge), Signature: s}
	}
	bad := []string{
		"vaultys://signfile?timestamp=1",                     // no hash
		"vaultys://signfile?nohash=" + good,                  // no hash param
		"vaultys://signfile?hash=" + good + "&hash=" + good,  // duplicate
		"vaultys://signfile?hash=00&hash=" + good,            // duplicate, first wrong
		"vaultys://signfile?x=1&hash=" + good + "0",          // wrong hash
		"vaultys://signfile",                                 // no query
		"vaultys://signfile?hash=" + good + "?hash=" + good,  // smuggled ?
		"vaultys://other?hash=" + good,                       // wrong host
		"https://signfile?hash=" + good,                      // wrong scheme
		"vaultys://signfile/x?hash=" + good,                  // path
		"vaultys://signfile?hash=" + good + "#hash=" + good,  // fragment
		"vaultys://signfile?hash=" + strings.Repeat("0", 64), // other hash
	}
	for _, c := range bad {
		if err := m.VerifyFile(other, signed(c), id, false); err == nil {
			t.Errorf("challenge %q accepted", c)
		}
	}
	ok := fmt.Sprintf("vaultys://signfile?hash=%s&timestamp=1", good)
	if err := m.VerifyFile(other, signed(ok), id, false); err != nil {
		t.Errorf("well-formed challenge rejected: %v", err)
	}
}

// Finding 6: backups must never be encrypted with an empty password.
func TestBackup_RejectsEmptyPassword(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.ExportBackup(""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("empty export password must be rejected, got %v", err)
	}
	backup, err := m.ExportBackup("pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportBackup(backup, ""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("empty import password must be rejected, got %v", err)
	}
	if _, err := ImportBackup(backup, "pw"); err != nil {
		t.Fatal(err)
	}
}

// Finding 5: the store file holds secrets.
func TestFileStore_PermissionsAndAtomicity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")

	fs, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := vaultysid.GeneratePerson()
	NewManager(id, fs)
	if err := fs.Save(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("store mode = %o, want 600", st.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}

	// Pre-existing world-readable store is tightened on load.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(path); err != nil {
		t.Fatal(err)
	}
	st, _ = os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("existing store not chmod 600: %o", st.Mode().Perm())
	}

	// A corrupt store is an error, not an empty store (which would be
	// overwritten on the next Save, destroying the secrets).
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(path); err == nil {
		t.Fatal("corrupt store must not load as empty")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "{not json" {
		t.Fatal("corrupt store was modified")
	}

	// Missing file is fine.
	if _, err := NewFileStore(filepath.Join(dir, "new.json")); err != nil {
		t.Fatal(err)
	}
}

func TestWriteSecretFile_ReplacesExistingMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteSecretFile(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	b, _ := os.ReadFile(path)
	if st.Mode().Perm() != 0o600 || string(b) != "new" {
		t.Fatalf("mode %o content %q", st.Mode().Perm(), b)
	}
}

// Finding 4: connect is a plain p2p/auth handshake with no secret in any
// challenge field, and saves the authenticated contact on both sides.
func TestConnect_HandshakeSavesContact(t *testing.T) {
	alice, aliceID := newTestManager(t)
	bob, bobID := newTestManager(t)

	var bobSaw []byte
	sessA, initMsg, err := alice.RequestConnect(bobID)
	if err != nil {
		t.Fatal(err)
	}
	init, err := challenger.Deserialize(initMsg)
	if err != nil {
		t.Fatal(err)
	}
	if init.Protocol != "p2p" || init.Service != "auth" {
		t.Fatalf("unexpected protocol/service %q/%q", init.Protocol, init.Service)
	}
	dh, _ := aliceID.DiffieHellman(bobID.GetCypherPublicKey())
	if strings.Contains(string(initMsg), hex.EncodeToString(dh)) || strings.Contains(string(initMsg), string(dh)) {
		t.Fatal("DH secret leaked into the challenge")
	}

	sessB, step1, err := bob.AcceptConnect(initMsg, func(remote *vaultysid.VaultysID) error {
		bobSaw = remote.ID()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(bobSaw) != string(aliceID.ID()) {
		t.Fatal("accept callback must get the remote (initiator) id")
	}

	completeMsg, gotBob, err := sessA.Complete(step1)
	if err != nil {
		t.Fatal(err)
	}
	if gotBob.DID() != bobID.DID() {
		t.Fatal("initiator authenticated the wrong contact")
	}
	gotAlice, err := sessB.Finalize(completeMsg)
	if err != nil {
		t.Fatal(err)
	}
	if gotAlice.DID() != aliceID.DID() {
		t.Fatal("responder authenticated the wrong contact")
	}

	if c, err := alice.GetContact(bobID.DID()); err != nil || c.DID() != bobID.DID() || !c.HasCertificate() {
		t.Fatalf("alice did not save bob with certificate: %v", err)
	}
	if c, err := bob.GetContact(aliceID.DID()); err != nil || !c.HasCertificate() {
		t.Fatalf("bob did not save alice with certificate: %v", err)
	}
	if alice.store.Get("connect_rand") != nil {
		t.Fatal("connect_rand must not be stored")
	}

	// Replaying the COMPLETE to a new responder session saves nothing.
	carol, _ := newTestManager(t)
	_, _, err = carol.AcceptConnect(completeMsg, nil)
	if err == nil {
		t.Fatal("first message must be INIT")
	}
}

func TestConnect_WrongPeerRejected(t *testing.T) {
	alice, _ := newTestManager(t)
	_, bobID := newTestManager(t)
	mallory, _ := newTestManager(t)

	sessA, initMsg, _ := alice.RequestConnect(bobID)
	_, step1, err := mallory.AcceptConnect(initMsg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sessA.Complete(step1); err == nil {
		t.Fatal("initiator must refuse a peer other than the requested contact")
	}
	if len(alice.Contacts()) != 0 {
		t.Fatal("no contact may be saved")
	}

	// Responder can refuse.
	_, initMsg, _ = alice.RequestConnect(nil)
	if _, _, err := mallory.AcceptConnect(initMsg, func(*vaultysid.VaultysID) error { return errors.New("no") }); err == nil {
		t.Fatal("refusal ignored")
	}

	// Wrong service is refused by AcceptConnect.
	ch := challenger.New(mustPerson(t))
	init, _ := ch.Init("p2p", "transfer")
	b, _ := challenger.Serialize(init)
	if _, _, err := mallory.AcceptConnect(b, nil); err == nil {
		t.Fatal("non auth service accepted")
	}
}

func mustPerson(t *testing.T) *vaultysid.VaultysID {
	id, err := vaultysid.GeneratePerson()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
