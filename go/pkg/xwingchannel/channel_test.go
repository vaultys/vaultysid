package xwingchannel

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/kem/xwing"
	"github.com/vaultys/vaultysid/go/pkg/challenger"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

// memoryTransport is one end of an in-memory message pipe.
type memoryTransport struct {
	in     chan []byte
	peer   *memoryTransport
	mu     sync.Mutex
	closed bool
	sent   [][]byte
	mutate func([]byte) []byte
}

func pipe() (*memoryTransport, *memoryTransport) {
	a := &memoryTransport{in: make(chan []byte, 64)}
	b := &memoryTransport{in: make(chan []byte, 64)}
	a.peer, b.peer = b, a
	return a, b
}

func (m *memoryTransport) Send(data []byte) error {
	m.mu.Lock()
	d := append([]byte(nil), data...)
	m.sent = append(m.sent, append([]byte(nil), data...))
	mutate := m.mutate
	m.mu.Unlock()
	if mutate != nil {
		if d = mutate(d); d == nil {
			return nil
		}
	}
	return m.peer.raw(d)
}

func (m *memoryTransport) raw(d []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("closed")
	}
	m.in <- d
	return nil
}

func (m *memoryTransport) Receive() ([]byte, error) {
	d, ok := <-m.in
	if !ok {
		return nil, errors.New("closed")
	}
	return d, nil
}

func (m *memoryTransport) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.in)
	}
	return nil
}

func readJSON(t *testing.T, name string, v interface{}) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "compatibility", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestXWingDraftVectors(t *testing.T) {
	var v struct {
		Vectors []struct{ Seed, Sk, Pk, Eseed, Ct, Ss string } `json:"vectors"`
	}
	readJSON(t, "xwing-draft-vectors.json", &v)
	for _, x := range v.Vectors {
		pk, sk, err := KeyPairFromSeed(unhex(t, x.Seed))
		if err != nil || hex.EncodeToString(pk) != x.Pk || hex.EncodeToString(sk) != x.Sk {
			t.Fatal("keygen mismatch")
		}
		ct, ss, err := EncapsulateWith(pk, unhex(t, x.Eseed))
		if err != nil || hex.EncodeToString(ct) != x.Ct || hex.EncodeToString(ss) != x.Ss {
			t.Fatal("encapsulate mismatch")
		}
		ss2, err := Decapsulate(unhex(t, x.Ct), unhex(t, x.Sk))
		if err != nil || hex.EncodeToString(ss2) != x.Ss {
			t.Fatal("decapsulate mismatch")
		}
	}
	_ = xwing.Scheme()
}

func fixed(b []byte) RandomSource {
	return func(n int) ([]byte, error) { return append([]byte(nil), b[:n]...), nil }
}

func TestChannelVectors(t *testing.T) {
	var v struct {
		InitiatorSeed, EncapsulationRandomness, M1, M2, SharedSecret, TranscriptHash, KeyI2R, KeyR2I, Binding string
		Records                                                                                               []struct {
			Direction string `json:"direction"`
			Seq       uint64 `json:"seq"`
			Message   string `json:"message"`
			Record    string `json:"record"`
		} `json:"records"`
	}
	readJSON(t, "xwing-channel-vectors.json", &v)
	a, b := pipe()
	var initiator, responder *Session
	var errI, errR error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		initiator, errI = InitiateWith(a, fixed(unhex(t, v.InitiatorSeed)), Options{})
	}()
	go func() {
		defer wg.Done()
		responder, errR = AcceptWith(b, fixed(unhex(t, v.EncapsulationRandomness)), Options{})
	}()
	wg.Wait()
	if errI != nil || errR != nil {
		t.Fatal(errI, errR)
	}
	if hex.EncodeToString(a.sent[0]) != v.M1 || hex.EncodeToString(b.sent[0]) != v.M2 {
		t.Fatal("M1/M2 differ from TypeScript")
	}
	if hex.EncodeToString(initiator.Binding) != v.Binding || hex.EncodeToString(responder.TranscriptHash) != v.TranscriptHash {
		t.Fatal("binding/transcript differ from TypeScript")
	}
	k := DeriveKeys(unhex(t, v.SharedSecret), unhex(t, v.M1), unhex(t, v.M2))
	if hex.EncodeToString(k.I2R) != v.KeyI2R || hex.EncodeToString(k.R2I) != v.KeyR2I {
		t.Fatal("keys differ")
	}
	for _, r := range v.Records {
		key := k.I2R
		if r.Direction == "r2i" {
			key = k.R2I
		}
		rec, err := EncryptRecord(key, r.Seq, unhex(t, r.Message))
		if err != nil || hex.EncodeToString(rec) != r.Record {
			t.Fatalf("record %s/%d differs", r.Direction, r.Seq)
		}
	}
	// the TypeScript i2r records decrypt in order on the Go responder
	for _, r := range v.Records {
		if r.Direction != "i2r" {
			continue
		}
		_ = b.peer.peer // keep linter quiet
		if err := a.peer.raw(unhex(t, r.Record)); err != nil {
			t.Fatal(err)
		}
		got, err := responder.Receive()
		if err != nil || hex.EncodeToString(got) != r.Message {
			t.Fatalf("Go could not read TypeScript record %d: %v", r.Seq, err)
		}
	}
}

func established(t *testing.T) (*memoryTransport, *memoryTransport, *Session, *Session) {
	a, b := pipe()
	var i, r *Session
	var e1, e2 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); i, e1 = Initiate(a, Options{}) }()
	go func() { defer wg.Done(); r, e2 = Accept(b, Options{}) }()
	wg.Wait()
	if e1 != nil || e2 != nil {
		t.Fatal(e1, e2)
	}
	return a, b, i, r
}

func TestChannelRefusals(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		_, _, i, r := established(t)
		_ = i.Send([]byte("ping"))
		if got, err := r.Receive(); err != nil || string(got) != "ping" {
			t.Fatal(err)
		}
	})
	t.Run("replay", func(t *testing.T) {
		a, _, i, r := established(t)
		_ = i.Send([]byte("once"))
		_, _ = r.Receive()
		_ = a.peer.raw(a.sent[len(a.sent)-1])
		if _, err := r.Receive(); !IsCode(err, CodeInvalidSequence) {
			t.Fatal(err)
		}
	})
	t.Run("reflection", func(t *testing.T) {
		a, _, i, _ := established(t)
		_ = i.Send([]byte("to responder"))
		_ = a.raw(a.sent[len(a.sent)-1])
		if _, err := i.Receive(); !IsCode(err, CodeAuthFailed) {
			t.Fatal(err)
		}
	})
	t.Run("tamper", func(t *testing.T) {
		a, _, i, r := established(t)
		a.mutate = func(d []byte) []byte { d[len(d)-1] ^= 1; return d }
		_ = i.Send([]byte("x"))
		if _, err := r.Receive(); !IsCode(err, CodeAuthFailed) {
			t.Fatal(err)
		}
		if _, err := r.Receive(); !IsCode(err, CodeChannelClosed) {
			t.Fatal(err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		a, _ := pipe()
		if _, err := Initiate(a, Options{Timeout: 50 * time.Millisecond}); !IsCode(err, CodeTimeout) {
			t.Fatal(err)
		}
	})
	t.Run("malformed M1", func(t *testing.T) {
		a, b := pipe()
		_ = a.Send(make([]byte, 10))
		if _, err := Accept(b, Options{}); !IsCode(err, CodeInvalidFormat) {
			t.Fatal(err)
		}
	})
}

const svc = "https://service.test"

func handshakePair(t *testing.T, user, server *vaultysid.VaultysID, userService, serverService string, opts HandshakeOptions) (*Result, error, *Result, error) {
	a, b := pipe()
	var ru, rs *Result
	var eu, es error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); ru, eu = ConnectOverXWing(user, a, userService, nil, opts) }()
	go func() {
		defer wg.Done()
		rs, es = AcceptOverXWing(server, b, serverService, nil, HandshakeOptions{Timeout: 2 * time.Second})
	}()
	wg.Wait()
	return ru, eu, rs, es
}

func TestBoundHandshake(t *testing.T) {
	user, _ := vaultysid.GeneratePerson()
	server, _ := vaultysid.GenerateOrganizationAlg("dilithium")
	ru, eu, rs, es := handshakePair(t, user, server, svc, svc, HandshakeOptions{ExpectedPeer: server})
	if eu != nil || es != nil {
		t.Fatal(eu, es)
	}
	if ru.Contact.DID() != server.DID() || rs.Contact.DID() != user.DID() {
		t.Fatal("wrong contacts")
	}
	cert, err := challenger.Deserialize(ru.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := cert.Metadata.PK1.Get(ServiceMetadataKey); v != svc {
		t.Fatal("service not signed by initiator")
	}
	if v, _ := cert.Metadata.PK2.Get(BindingMetadataKey); v != base64.StdEncoding.EncodeToString(ru.Session.Binding) {
		t.Fatal("binding not signed by responder")
	}
	_ = ru.Session.Send([]byte("after"))
	if got, err := rs.Session.Receive(); err != nil || !bytes.Equal(got, []byte("after")) {
		t.Fatal(err)
	}
}

func TestBoundHandshakeRefusals(t *testing.T) {
	user, _ := vaultysid.GeneratePerson()
	server, _ := vaultysid.GenerateOrganization()
	other, _ := vaultysid.GenerateOrganization()
	t.Run("other service", func(t *testing.T) {
		_, _, _, es := handshakePair(t, user, server, svc, "https://other.test", HandshakeOptions{Timeout: 2 * time.Second})
		if !IsCode(es, CodeServiceMismatch) {
			t.Fatal(es)
		}
	})
	t.Run("unexpected peer", func(t *testing.T) {
		_, eu, _, _ := handshakePair(t, user, server, svc, svc, HandshakeOptions{ExpectedPeer: other, Timeout: 2 * time.Second})
		if !IsCode(eu, CodePeerMismatch) {
			t.Fatal(eu)
		}
	})
	t.Run("non-canonical service", func(t *testing.T) {
		a, _ := pipe()
		if _, err := ConnectOverXWing(user, a, "https://Service.test/", nil, HandshakeOptions{}); !IsCode(err, CodeInvalidServiceID) {
			t.Fatal(err)
		}
		if _, err := ConnectOverXWing(user, a, svc, map[string]string{ServiceMetadataKey: "x"}, HandshakeOptions{}); !IsCode(err, CodeInvalidArgument) {
			t.Fatal(err)
		}
	})
	t.Run("relayed between two channels", func(t *testing.T) {
		toUser1, toUser2 := pipe()
		toServer1, toServer2 := pipe()
		var wg sync.WaitGroup
		var es error
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, _ = ConnectOverXWing(user, toUser1, svc, nil, HandshakeOptions{Timeout: 2 * time.Second})
		}()
		go func() {
			defer wg.Done()
			_, es = AcceptOverXWing(server, toServer2, svc, nil, HandshakeOptions{Timeout: 2 * time.Second})
		}()
		go func() {
			defer wg.Done()
			var withUser, withServer *Session
			var w sync.WaitGroup
			w.Add(2)
			go func() { defer w.Done(); withUser, _ = Accept(toUser2, Options{}) }()
			go func() { defer w.Done(); withServer, _ = Initiate(toServer1, Options{}) }()
			w.Wait()
			if withUser == nil || withServer == nil {
				return
			}
			if m, err := withUser.Receive(); err == nil {
				_ = withServer.Send(m)
			}
			if m, err := withServer.Receive(); err == nil {
				_ = withUser.Send(m)
			}
			_ = withUser.Close()
			_ = withServer.Close()
		}()
		wg.Wait()
		if !IsCode(es, CodeBindingMismatch) {
			t.Fatal(es)
		}
	})
}
