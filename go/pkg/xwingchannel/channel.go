// Package xwingchannel implements the X-Wing secure channel and the handshake
// bound to it (rfc/SECURE-CHANNEL.md), byte-compatible with the TypeScript
// reference (typescript/src/xwingChannel.ts).
package xwingchannel

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/xwing"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	ChannelLabel    = "vaultysid/xwing-channel/v1"
	ChannelLabelI2R = "vaultysid/xwing-channel/v1/i2r"
	ChannelLabelR2I = "vaultysid/xwing-channel/v1/r2i"
	BindingLabel    = "vaultysid/xwing-binding/v1"

	PublicKeyLength               = 1216
	SeedLength                    = 32
	CipherTextLength              = 1120
	EncapsulationRandomnessLength = 64

	headerLength = 2
	seqLength    = 8
	tagLength    = 16
	keyLength    = 32

	M1Length       = headerLength + PublicKeyLength
	M2Length       = headerLength + CipherTextLength
	RecordOverhead = headerLength + seqLength + tagLength

	DefaultTimeout = 30 * time.Second
	maxSeq         = 1<<53 - 1 // same bound as the TypeScript reference (Number.MAX_SAFE_INTEGER)
)

var header = []byte{0x01, 0x01}

// Error codes, identical to the TypeScript reference.
const (
	CodeInvalidArgument  = "INVALID_ARGUMENT"
	CodeInvalidFormat    = "INVALID_FORMAT"
	CodeInvalidKey       = "INVALID_KEY"
	CodeInvalidSequence  = "INVALID_SEQUENCE"
	CodeInvalidServiceID = "INVALID_SERVICE_ID"
	CodeAuthFailed       = "AUTH_FAILED"
	CodeChannelClosed    = "CHANNEL_CLOSED"
	CodeTimeout          = "TIMEOUT"
	CodeBindingMismatch  = "BINDING_MISMATCH"
	CodeServiceMismatch  = "SERVICE_MISMATCH"
	CodePeerMismatch     = "PEER_MISMATCH"
	CodeHandshakeFailed  = "HANDSHAKE_FAILED"
)

// Error is a channel error with a stable code.
type Error struct{ Code string }

func (e *Error) Error() string { return "xwing channel: " + e.Code }

// IsCode reports whether err is a channel Error with that code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

func fail(code string) error { return &Error{Code: code} }

// Transport is the message channel the X-Wing channel runs over.
type Transport interface {
	Send(data []byte) error
	Receive() ([]byte, error)
	Close() error
}

func lp(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func wipe(bufs ...[]byte) {
	for _, b := range bufs {
		for i := range b {
			b[i] = 0
		}
	}
}

func isZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

// KeyPairFromSeed derives the X-Wing key pair of a 32-byte seed (refuses a zero seed).
func KeyPairFromSeed(seed []byte) (publicKey, secretKey []byte, err error) {
	if len(seed) != SeedLength || isZero(seed) {
		return nil, nil, fail(CodeInvalidKey)
	}
	sk, pk := xwing.DeriveKeyPairPacked(seed)
	return pk, sk, nil
}

// EncapsulateWith encapsulates to publicKey with explicit 64-byte randomness.
func EncapsulateWith(publicKey, randomness []byte) (cipherText, sharedSecret []byte, err error) {
	if len(publicKey) != PublicKeyLength {
		return nil, nil, fail(CodeInvalidKey)
	}
	if len(randomness) != EncapsulationRandomnessLength {
		return nil, nil, fail(CodeInvalidArgument)
	}
	ss, ct, err := xwing.Encapsulate(publicKey, randomness)
	if err != nil {
		return nil, nil, fail(CodeInvalidKey)
	}
	if isZero(ss) {
		return nil, nil, fail(CodeInvalidKey)
	}
	return ct, ss, nil
}

// Decapsulate recovers the shared secret (implicit rejection: a tampered ML-KEM
// ciphertext gives another secret, it does not fail).
func Decapsulate(cipherText, secretKey []byte) ([]byte, error) {
	if len(secretKey) != SeedLength {
		return nil, fail(CodeInvalidKey)
	}
	if len(cipherText) != CipherTextLength {
		return nil, fail(CodeInvalidFormat)
	}
	ss := xwing.Decapsulate(cipherText, secretKey)
	if ss == nil || isZero(ss) {
		return nil, fail(CodeInvalidFormat)
	}
	return ss, nil
}

// Keys are the session keys of a channel.
type Keys struct {
	TranscriptHash []byte
	I2R, R2I       []byte
	Binding        []byte
}

// DeriveKeys derives the directional keys and binding value of a session.
func DeriveKeys(sharedSecret, m1, m2 []byte) Keys {
	h := sha256.New()
	h.Write(lp([]byte(ChannelLabel)))
	h.Write(lp(m1))
	h.Write(lp(m2))
	th := h.Sum(nil)
	prk := hkdf.Extract(sha256.New, sharedSecret, th)
	defer wipe(prk)
	expand := func(label string) []byte {
		out := make([]byte, keyLength)
		if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte(label)), out); err != nil {
			panic(err)
		}
		return out
	}
	b := sha256.New()
	b.Write(lp([]byte(BindingLabel)))
	b.Write(th)
	return Keys{TranscriptHash: th, I2R: expand(ChannelLabelI2R), R2I: expand(ChannelLabelR2I), Binding: b.Sum(nil)}
}

func recordNonce(seq []byte) []byte {
	n := make([]byte, chacha20poly1305.NonceSizeX)
	copy(n[16:], seq)
	return n
}

// EncryptRecord encrypts one record (exported for test vectors).
func EncryptRecord(key []byte, seq uint64, message []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	aad := make([]byte, headerLength+seqLength)
	copy(aad, header)
	binary.BigEndian.PutUint64(aad[headerLength:], seq)
	return aead.Seal(append([]byte(nil), aad...), recordNonce(aad[headerLength:]), message, aad), nil
}

// Session is an established X-Wing channel: an encrypted, ordered Transport.
// It is authenticated only by the bound handshake (ConnectOverXWing / AcceptOverXWing).
type Session struct {
	Role           string // "initiator" or "responder"
	Binding        []byte
	TranscriptHash []byte

	transport  Transport
	mu         sync.Mutex
	sendKey    []byte
	receiveKey []byte
	sendSeq    uint64
	receiveSeq uint64
	closed     bool
}

func newSession(t Transport, role string, k Keys) *Session {
	s := &Session{Role: role, Binding: k.Binding, TranscriptHash: k.TranscriptHash, transport: t}
	if role == "initiator" {
		s.sendKey, s.receiveKey = k.I2R, k.R2I
	} else {
		s.sendKey, s.receiveKey = k.R2I, k.I2R
	}
	return s
}

// Send encrypts and sends one message.
func (s *Session) Send(data []byte) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fail(CodeChannelClosed)
	}
	if s.sendSeq > maxSeq {
		s.mu.Unlock()
		return fail(CodeInvalidSequence)
	}
	seq := s.sendSeq
	s.sendSeq++
	record, err := EncryptRecord(s.sendKey, seq, data)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.transport.Send(record)
}

// Receive receives and decrypts one message. Any failure closes the session.
func (s *Session) Receive() ([]byte, error) {
	if s.isClosed() {
		return nil, fail(CodeChannelClosed)
	}
	record, err := s.transport.Receive()
	if s.isClosed() {
		return nil, fail(CodeChannelClosed)
	}
	if err != nil || len(record) == 0 {
		return nil, s.failClose(CodeChannelClosed)
	}
	if len(record) < RecordOverhead || !bytes.Equal(record[:headerLength], header) {
		return nil, s.failClose(CodeInvalidFormat)
	}
	seq := binary.BigEndian.Uint64(record[headerLength:])
	s.mu.Lock()
	expected := s.receiveSeq
	key := s.receiveKey
	s.mu.Unlock()
	if seq > maxSeq || seq != expected {
		return nil, s.failClose(CodeInvalidSequence)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, s.failClose(CodeAuthFailed)
	}
	aad := record[:headerLength+seqLength]
	plain, err := aead.Open(nil, recordNonce(aad[headerLength:]), record[headerLength+seqLength:], aad)
	if err != nil {
		return nil, s.failClose(CodeAuthFailed)
	}
	s.mu.Lock()
	s.receiveSeq++
	s.mu.Unlock()
	return plain, nil
}

// Close closes the session and erases its keys.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	wipe(s.sendKey, s.receiveKey)
	s.mu.Unlock()
	return s.transport.Close()
}

func (s *Session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Session) failClose(code string) error {
	_ = s.Close()
	return fail(code)
}

// receiveWithTimeout waits for one message at most timeout; on timeout the transport is closed.
func receiveWithTimeout(t Transport, timeout time.Duration) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		d, err := t.Receive()
		ch <- result{d, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.data, r.err
	case <-timer.C:
		_ = t.Close()
		return nil, fail(CodeTimeout)
	}
}

// Options of channel establishment.
type Options struct {
	// Timeout for the peer's establishment message (default 30 s, at most 10 min).
	Timeout time.Duration
}

func timeoutOf(d time.Duration) (time.Duration, error) {
	if d == 0 {
		return DefaultTimeout, nil
	}
	if d < time.Millisecond || d > 10*time.Minute {
		return 0, fail(CodeInvalidArgument)
	}
	return d, nil
}

// RandomSource returns n random bytes.
type RandomSource func(n int) ([]byte, error)

// CryptoRandom reads from crypto/rand.
func CryptoRandom(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}

// InitiateWith establishes a channel as initiator with an explicit random source (test vectors only).
func InitiateWith(t Transport, rng RandomSource, opts Options) (*Session, error) {
	timeout, err := timeoutOf(opts.Timeout)
	if err != nil {
		return nil, err
	}
	seed, err := rng(SeedLength)
	if err != nil {
		return nil, err
	}
	defer wipe(seed)
	pk, sk, err := KeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	defer wipe(sk)
	m1 := append(append([]byte(nil), header...), pk...)
	if err := t.Send(m1); err != nil {
		return nil, fail(CodeChannelClosed)
	}
	m2, err := receiveWithTimeout(t, timeout)
	if err != nil {
		_ = t.Close()
		if IsCode(err, CodeTimeout) {
			return nil, err
		}
		return nil, fail(CodeChannelClosed)
	}
	if len(m2) != M2Length || !bytes.Equal(m2[:headerLength], header) {
		_ = t.Close()
		return nil, fail(CodeInvalidFormat)
	}
	ss, err := Decapsulate(m2[headerLength:], sk)
	if err != nil {
		_ = t.Close()
		return nil, fail(CodeInvalidFormat)
	}
	defer wipe(ss)
	return newSession(t, "initiator", DeriveKeys(ss, m1, m2)), nil
}

// AcceptWith establishes a channel as responder with an explicit random source (test vectors only).
func AcceptWith(t Transport, rng RandomSource, opts Options) (*Session, error) {
	timeout, err := timeoutOf(opts.Timeout)
	if err != nil {
		return nil, err
	}
	m1, err := receiveWithTimeout(t, timeout)
	if err != nil {
		_ = t.Close()
		if IsCode(err, CodeTimeout) {
			return nil, err
		}
		return nil, fail(CodeChannelClosed)
	}
	if len(m1) != M1Length || !bytes.Equal(m1[:headerLength], header) {
		_ = t.Close()
		return nil, fail(CodeInvalidFormat)
	}
	randomness, err := rng(EncapsulationRandomnessLength)
	if err != nil {
		return nil, err
	}
	defer wipe(randomness)
	ct, ss, err := EncapsulateWith(m1[headerLength:], randomness)
	if err != nil {
		_ = t.Close()
		return nil, err
	}
	defer wipe(ss)
	m2 := append(append([]byte(nil), header...), ct...)
	if err := t.Send(m2); err != nil {
		return nil, fail(CodeChannelClosed)
	}
	return newSession(t, "responder", DeriveKeys(ss, m1, m2)), nil
}

// Initiate establishes a channel as initiator. NOT authenticated by itself.
func Initiate(t Transport, opts Options) (*Session, error) {
	return InitiateWith(t, CryptoRandom, opts)
}

// Accept establishes a channel as responder. NOT authenticated by itself.
func Accept(t Transport, opts Options) (*Session, error) { return AcceptWith(t, CryptoRandom, opts) }
