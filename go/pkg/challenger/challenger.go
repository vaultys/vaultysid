package challenger

import (
	"bytes"
	"crypto/subtle"
	"fmt"

	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
	"github.com/vmihailenco/msgpack/v5"
)

// Challenger implements the VaultysID mutual-authentication handshake
// (cross-language security spec §1).
//
// State machine (anything else sets ERROR, which is terminal):
//
//	Initiator: UNINITIALISED --Init-->           INIT
//	           INIT          --Step2(STEP1)-->   COMPLETE
//	Responder: UNINITIALISED --Step1(INIT)-->    STEP1
//	           STEP1         --Finalize(COMPLETE)--> COMPLETE
//
// Signatures are SignHandshake/VerifyHandshake over SerializeUnsigned, the
// canonical msgpack encoding of {version, protocol, service, timestamp, pk1,
// pk2, nonce, metadata} that byte-matches the TypeScript reference.
type Challenger struct {
	vaultysID *vaultysid.VaultysID
	myID      []byte
	options   *ChallengerOptions

	state     int
	challenge *Challenge // last message we produced (INIT / STEP1 / COMPLETE)
	remoteID  []byte
	metadata  map[string]string
	err       error
}

// NewChallenger creates a new Challenger instance
func NewChallenger(vid *vaultysid.VaultysID, opts *ChallengerOptions) *Challenger {
	if opts == nil {
		opts = DefaultOptions()
	}
	if opts.TimeWindow <= 0 {
		opts.TimeWindow = DefaultOptions().TimeWindow
	}
	return &Challenger{
		vaultysID: vid,
		myID:      vid.ToBytes(),
		options:   opts,
		state:     StateUninitialized,
		metadata:  make(map[string]string),
	}
}

// New creates a new Challenger instance with default options
func New(vid *vaultysid.VaultysID) *Challenger {
	return NewChallenger(vid, nil)
}

// fail moves the challenger to the terminal ERROR state.
func (c *Challenger) fail(format string, args ...interface{}) error {
	err := fmt.Errorf(format, args...)
	c.state = StateError
	c.err = err
	c.remoteID = nil
	return err
}

// Init starts a handshake as initiator and returns the INIT message.
func (c *Challenger) Init(protocol, service string) (*Challenge, error) {
	if c.state != StateUninitialized {
		return nil, c.fail("challenger already initialized")
	}
	if protocol == "" || service == "" {
		return nil, c.fail("protocol and service are required")
	}

	nonce, err := crypto.RandomBytes(nonceHalfSize)
	if err != nil {
		return nil, c.fail("failed to generate nonce: %w", err)
	}

	challenge := &Challenge{
		Version:   ProtocolV1,
		Protocol:  protocol,
		Service:   service,
		Timestamp: uint64(crypto.Now()),
		PK1:       cloneBytes(c.myID),
		Nonce:     nonce,
		Metadata: ChallengeMetadata{
			PK1: NewMetadata(c.metadata),
		},
		State: StateInit,
	}

	c.challenge = challenge
	c.state = StateInit
	return challenge.Clone(), nil
}

// Step1 (responder) processes an INIT message and returns the STEP1 message.
func (c *Challenger) Step1(initChallenge *Challenge) (*Challenge, error) {
	if c.state != StateUninitialized {
		return nil, c.fail("unexpected INIT: challenger is not uninitialised (state %d)", c.state)
	}
	if initChallenge == nil {
		return nil, c.fail("nil challenge")
	}
	if err := checkStructure(initChallenge, StateInit); err != nil {
		return nil, c.fail("invalid INIT: %w", err)
	}
	if err := c.validateTimestamp(initChallenge.Timestamp); err != nil {
		return nil, c.fail("invalid INIT: %w", err)
	}
	if bytes.Equal(initChallenge.PK1, c.myID) {
		return nil, c.fail("invalid INIT: pk1 is our own identity (reflection)")
	}
	remote, err := vaultysid.FromID(initChallenge.PK1, nil)
	if err != nil {
		return nil, c.fail("invalid INIT: unparseable pk1: %w", err)
	}
	if c.options.Accept != nil {
		if err := c.options.Accept(remote, initChallenge.Protocol, initChallenge.Service); err != nil {
			return nil, c.fail("remote refused: %w", err)
		}
	}

	ourNonce, err := crypto.RandomBytes(nonceHalfSize)
	if err != nil {
		return nil, c.fail("failed to generate nonce: %w", err)
	}
	nonce := make([]byte, 0, 2*nonceHalfSize)
	nonce = append(nonce, initChallenge.Nonce...)
	nonce = append(nonce, ourNonce...)

	step1 := &Challenge{
		Version:   ProtocolV1,
		Protocol:  initChallenge.Protocol,
		Service:   initChallenge.Service,
		Timestamp: initChallenge.Timestamp,
		PK1:       cloneBytes(initChallenge.PK1),
		PK2:       cloneBytes(c.myID),
		Nonce:     nonce,
		Metadata: ChallengeMetadata{
			PK1: initChallenge.Metadata.PK1.Clone(),
			PK2: NewMetadata(c.metadata),
		},
		State: StateStep1,
	}

	unsigned, err := SerializeUnsigned(step1)
	if err != nil {
		return nil, c.fail("failed to serialize challenge: %w", err)
	}
	step1.Sign2, err = c.vaultysID.SignHandshake(unsigned)
	if err != nil {
		return nil, c.fail("failed to sign challenge: %w", err)
	}

	c.challenge = step1
	c.remoteID = cloneBytes(step1.PK1)
	c.state = StateStep1
	return step1.Clone(), nil
}

// Step2 (initiator) processes the STEP1 message and returns the COMPLETE message.
func (c *Challenger) Step2(step1Challenge *Challenge) (*Challenge, error) {
	if c.state != StateInit {
		return nil, c.fail("unexpected STEP1: challenger is not in INIT state (state %d)", c.state)
	}
	if step1Challenge == nil {
		return nil, c.fail("nil challenge")
	}
	if err := checkStructure(step1Challenge, StateStep1); err != nil {
		return nil, c.fail("invalid STEP1: %w", err)
	}

	sent := c.challenge
	switch {
	case step1Challenge.Version != sent.Version:
		return nil, c.fail("invalid STEP1: version has been tampered with")
	case step1Challenge.Protocol != sent.Protocol:
		return nil, c.fail("invalid STEP1: protocol has been tampered with")
	case step1Challenge.Service != sent.Service:
		return nil, c.fail("invalid STEP1: service has been tampered with")
	case step1Challenge.Timestamp != sent.Timestamp:
		return nil, c.fail("invalid STEP1: timestamp has been tampered with")
	case !bytes.Equal(step1Challenge.PK1, sent.PK1):
		return nil, c.fail("invalid STEP1: pk1 has been tampered with")
	case !step1Challenge.Metadata.PK1.Equal(sent.Metadata.PK1):
		return nil, c.fail("invalid STEP1: metadata.pk1 has been tampered with")
	case subtle.ConstantTimeCompare(step1Challenge.Nonce[:nonceHalfSize], sent.Nonce) != 1:
		return nil, c.fail("invalid STEP1: nonce has been tampered with")
	case bytes.Equal(step1Challenge.PK2, c.myID):
		return nil, c.fail("invalid STEP1: pk2 is our own identity (reflection)")
	}
	if err := c.validateTimestamp(step1Challenge.Timestamp); err != nil {
		return nil, c.fail("invalid STEP1: %w", err)
	}

	remote, err := vaultysid.FromID(step1Challenge.PK2, nil)
	if err != nil {
		return nil, c.fail("invalid STEP1: unparseable pk2: %w", err)
	}

	unsigned, err := SerializeUnsigned(step1Challenge)
	if err != nil {
		return nil, c.fail("failed to serialize challenge: %w", err)
	}
	if err := remote.VerifyHandshake(unsigned, step1Challenge.Sign2); err != nil {
		return nil, c.fail("invalid STEP1: sign2 verification failed: %w", err)
	}

	if c.options.Accept != nil {
		if err := c.options.Accept(remote, sent.Protocol, sent.Service); err != nil {
			return nil, c.fail("remote refused: %w", err)
		}
	}

	sign1, err := c.vaultysID.SignHandshake(unsigned)
	if err != nil {
		return nil, c.fail("failed to sign challenge: %w", err)
	}

	complete := step1Challenge.Clone()
	complete.Sign1 = sign1
	complete.State = StateComplete
	complete.Error = ""

	c.challenge = complete
	c.remoteID = cloneBytes(complete.PK2)
	c.state = StateComplete
	return complete.Clone(), nil
}

// Finalize (responder) processes the COMPLETE message.
//
// Every field must be identical to the STEP1 message this challenger
// produced, and sign1 must verify; a COMPLETE received in any other state
// (including UNINITIALISED, i.e. a replayed certificate) is rejected.
func (c *Challenger) Finalize(completeChallenge *Challenge) error {
	if c.state != StateStep1 {
		return c.fail("unexpected COMPLETE: challenger is not in STEP1 state (state %d)", c.state)
	}
	if completeChallenge == nil {
		return c.fail("nil challenge")
	}
	if err := checkStructure(completeChallenge, StateComplete); err != nil {
		return c.fail("invalid COMPLETE: %w", err)
	}

	sent := c.challenge
	switch {
	case completeChallenge.Version != sent.Version:
		return c.fail("invalid COMPLETE: version has been tampered with")
	case completeChallenge.Protocol != sent.Protocol:
		return c.fail("invalid COMPLETE: protocol has been tampered with")
	case completeChallenge.Service != sent.Service:
		return c.fail("invalid COMPLETE: service has been tampered with")
	case completeChallenge.Timestamp != sent.Timestamp:
		return c.fail("invalid COMPLETE: timestamp has been tampered with")
	case !bytes.Equal(completeChallenge.PK1, sent.PK1):
		return c.fail("invalid COMPLETE: pk1 has been tampered with")
	case !bytes.Equal(completeChallenge.PK2, sent.PK2):
		return c.fail("invalid COMPLETE: pk2 has been tampered with")
	case subtle.ConstantTimeCompare(completeChallenge.Nonce, sent.Nonce) != 1:
		return c.fail("invalid COMPLETE: nonce has been tampered with")
	case !completeChallenge.Metadata.Equal(sent.Metadata):
		return c.fail("invalid COMPLETE: metadata has been tampered with")
	case !bytes.Equal(completeChallenge.Sign2, sent.Sign2):
		return c.fail("invalid COMPLETE: sign2 has been tampered with")
	}

	remote, err := vaultysid.FromID(sent.PK1, nil)
	if err != nil {
		return c.fail("invalid COMPLETE: unparseable pk1: %w", err)
	}
	unsigned, err := SerializeUnsigned(sent)
	if err != nil {
		return c.fail("failed to serialize challenge: %w", err)
	}
	if err := remote.VerifyHandshake(unsigned, completeChallenge.Sign1); err != nil {
		return c.fail("invalid COMPLETE: sign1 verification failed: %w", err)
	}

	complete := sent.Clone()
	complete.Sign1 = cloneBytes(completeChallenge.Sign1)
	complete.State = StateComplete

	c.challenge = complete
	c.remoteID = cloneBytes(complete.PK1)
	c.state = StateComplete
	return nil
}

// Process handles an incoming challenge and returns the appropriate response
// (nil after a successful Finalize). The message's own state only selects
// the transition; the challenger's state machine decides whether it is legal.
func (c *Challenger) Process(incoming *Challenge) (*Challenge, error) {
	if incoming == nil {
		return nil, c.fail("nil challenge")
	}
	switch incoming.State {
	case StateInit:
		return c.Step1(incoming)
	case StateStep1:
		return c.Step2(incoming)
	case StateComplete:
		if err := c.Finalize(incoming); err != nil {
			return nil, err
		}
		return nil, nil
	default:
		return nil, c.fail("invalid challenge state: %d", incoming.State)
	}
}

// Accept deserializes the next protocol message received from the peer of
// this live session and processes it through the state machine (see
// Process). It returns the message to send back, or nil after the
// responder's successful Finalize.
//
// To merely inspect or verify a stored certificate without touching any
// session, use VerifyCertificate.
func (c *Challenger) Accept(challengeBytes []byte) (*Challenge, error) {
	challenge, err := Deserialize(challengeBytes)
	if err != nil {
		return nil, c.fail("failed to deserialize challenge: %w", err)
	}
	return c.Process(challenge)
}

// GetState returns the current challenger state
func (c *Challenger) GetState() int {
	return c.state
}

// Err returns the error that moved the challenger to ERROR, if any.
func (c *Challenger) Err() error {
	return c.err
}

// HasFailed returns true if the challenger is in the terminal ERROR state.
func (c *Challenger) HasFailed() bool {
	return c.state == StateError
}

// GetRemoteID returns the authenticated remote identity bytes. It is only
// available once the handshake is COMPLETE.
func (c *Challenger) GetRemoteID() []byte {
	if c.state != StateComplete {
		return nil
	}
	return cloneBytes(c.remoteID)
}

// GetRemoteVaultysID returns the authenticated remote VaultysID, carrying
// the handshake certificate. Only available once COMPLETE.
func (c *Challenger) GetRemoteVaultysID() (*vaultysid.VaultysID, error) {
	if c.state != StateComplete || c.remoteID == nil {
		return nil, fmt.Errorf("handshake is not complete")
	}
	cert, err := c.GetCertificate()
	if err != nil {
		return nil, err
	}
	return vaultysid.FromID(c.remoteID, cert)
}

// GetCertificate returns the serialized COMPLETE certificate.
func (c *Challenger) GetCertificate() ([]byte, error) {
	if c.state != StateComplete || c.challenge == nil {
		return nil, fmt.Errorf("handshake is not complete")
	}
	return Serialize(c.challenge)
}

// GetContext returns the protocol, service and metadata of the current session.
func (c *Challenger) GetContext() (protocol, service string, metadata ChallengeMetadata) {
	if c.challenge == nil {
		return "", "", ChallengeMetadata{}
	}
	return c.challenge.Protocol, c.challenge.Service, ChallengeMetadata{
		PK1: c.challenge.Metadata.PK1.Clone(),
		PK2: c.challenge.Metadata.PK2.Clone(),
	}
}

// IsComplete returns true if the challenge protocol is complete
func (c *Challenger) IsComplete() bool {
	return c.state == StateComplete
}

// Reset discards the session and returns the challenger to UNINITIALISED.
func (c *Challenger) Reset() {
	c.state = StateUninitialized
	c.challenge = nil
	c.remoteID = nil
	c.err = nil
	c.metadata = make(map[string]string)
}

// SetMetadata sets our own metadata, included in the next INIT or STEP1 we produce.
func (c *Challenger) SetMetadata(key, value string) {
	c.metadata[key] = value
}

// GetMetadata gets one of our own metadata values
func (c *Challenger) GetMetadata(key string) (string, bool) {
	val, ok := c.metadata[key]
	return val, ok
}

// validateTimestamp checks the timestamp (Unix ms) against the liveliness window.
func (c *Challenger) validateTimestamp(timestamp uint64) error {
	return validateTimestampWindow(timestamp, c.options.TimeWindow.Milliseconds())
}

func validateTimestampWindow(timestamp uint64, maxDiff int64) error {
	now := crypto.Now()
	if timestamp > uint64(1)<<62 {
		return fmt.Errorf("timestamp out of range")
	}
	diff := now - int64(timestamp)
	if diff < 0 {
		diff = -diff
	}
	if diff >= maxDiff {
		return fmt.Errorf("timestamp outside allowed window: %d ms", diff)
	}
	return nil
}

// checkStructure validates the fields a message in the given state must
// (and must not) carry. It performs no signature verification.
func checkStructure(c *Challenge, state int) error {
	if c.Version != ProtocolV1 {
		return fmt.Errorf("unsupported challenge version %d", c.Version)
	}
	if c.Protocol == "" || c.Service == "" || c.Timestamp == 0 {
		return fmt.Errorf("missing protocol, service or timestamp")
	}
	if !c.HasPK1() {
		return fmt.Errorf("missing pk1")
	}
	switch state {
	case StateInit:
		if c.HasPK2() || c.HasSign1() || c.HasSign2() {
			return fmt.Errorf("INIT must not carry pk2 or signatures")
		}
		if len(c.Nonce) != nonceHalfSize {
			return fmt.Errorf("INIT nonce must be %d bytes", nonceHalfSize)
		}
		if c.Metadata.PK2 != nil {
			return fmt.Errorf("INIT must not carry metadata.pk2")
		}
	case StateStep1:
		if !c.HasPK2() || !c.HasSign2() || c.HasSign1() {
			return fmt.Errorf("STEP1 must carry pk2 and sign2 only")
		}
		if len(c.Nonce) != 2*nonceHalfSize {
			return fmt.Errorf("STEP1 nonce must be %d bytes", 2*nonceHalfSize)
		}
	case StateComplete:
		if !c.HasPK2() || !c.HasSign1() || !c.HasSign2() {
			return fmt.Errorf("COMPLETE must carry pk2, sign1 and sign2")
		}
		if len(c.Nonce) != 2*nonceHalfSize {
			return fmt.Errorf("COMPLETE nonce must be %d bytes", 2*nonceHalfSize)
		}
	default:
		return fmt.Errorf("invalid state %d", state)
	}
	return nil
}

// marshalCompact encodes v the way TS's @msgpack/msgpack does: integers use
// the smallest representation that fits the value (e.g. version=1 encodes as
// a bare 0x01 positive fixint, not vmihailenco's default 0xcc 0x01 uint8
// tag). Without this, integer fields encode to different bytes than TS for
// the identical value, which breaks byte-exact signature verification.
func marshalCompact(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := msgpack.NewEncoder(&buf)
	enc.UseCompactInts(true)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Serialize serializes a challenge to its wire format. The Challenge struct
// tags declare TS's field order and per-state field set (pk2/sign1/sign2
// omitted when empty; State/Error excluded).
func Serialize(challenge *Challenge) ([]byte, error) {
	return marshalCompact(challenge)
}

// orderedChallengeData is the unsigned view of a challenge, in TS field order:
// version, protocol, service, timestamp, pk1, pk2, nonce, metadata.
type orderedChallengeData struct {
	Version   uint8             `msgpack:"version"`
	Protocol  string            `msgpack:"protocol"`
	Service   string            `msgpack:"service"`
	Timestamp uint64            `msgpack:"timestamp"`
	PK1       []byte            `msgpack:"pk1"`
	PK2       []byte            `msgpack:"pk2"`
	Nonce     []byte            `msgpack:"nonce"`
	Metadata  ChallengeMetadata `msgpack:"metadata"`
}

// SerializeUnsigned returns the bytes both parties sign: byte-for-byte the
// TypeScript v1 `serializeUnsigned`, i.e. msgpack of {version, protocol,
// service, timestamp, pk1, pk2, nonce, metadata}, metadata INCLUDED exactly
// as carried by the challenge (presence and entry order preserved).
func SerializeUnsigned(challenge *Challenge) ([]byte, error) {
	if challenge.Version != ProtocolV1 {
		return nil, fmt.Errorf("unsupported challenge version %d", challenge.Version)
	}
	return marshalCompact(orderedChallengeData{
		Version:   challenge.Version,
		Protocol:  challenge.Protocol,
		Service:   challenge.Service,
		Timestamp: challenge.Timestamp,
		PK1:       challenge.PK1,
		PK2:       challenge.PK2,
		Nonce:     challenge.Nonce,
		Metadata:  challenge.Metadata,
	})
}

// Deserialize parses a challenge, infers its state from the fields present
// and validates it. For STEP1 and COMPLETE messages the signatures present
// are verified. Deserialize is read-only and never panics on malformed
// input; on failure it returns the partially-decoded challenge in
// StateError together with the error.
func Deserialize(data []byte) (ch *Challenge, err error) {
	defer func() {
		// Defensive: a parser bug must not become a remote crash.
		if r := recover(); r != nil {
			ch, err = &Challenge{State: StateError, Error: "malformed challenge"}, fmt.Errorf("malformed challenge: %v", r)
		}
	}()

	var challenge Challenge
	if err := msgpack.Unmarshal(data, &challenge); err != nil {
		return &Challenge{State: StateError, Error: err.Error()}, fmt.Errorf("failed to unmarshal challenge: %w", err)
	}

	if err := validateAndSetState(&challenge); err != nil {
		challenge.State = StateError
		challenge.Error = err.Error()
		return &challenge, err
	}

	return &challenge, nil
}

// VerifyCertificate deserializes a COMPLETE certificate and verifies both
// handshake signatures. It is read-only: it never affects any live
// session, never signs, and works with public-only identities. Liveliness
// is not checked (certificates are long-lived records).
func VerifyCertificate(certificate []byte) (*Challenge, error) {
	ch, err := Deserialize(certificate)
	if err != nil {
		return nil, err
	}
	if ch.State != StateComplete {
		return nil, fmt.Errorf("certificate is not a COMPLETE handshake")
	}
	return ch, nil
}

// validateAndSetState determines the state based on challenge fields and
// verifies whichever signatures are present.
func validateAndSetState(c *Challenge) error {
	var state int
	switch {
	case c.HasPK1() && !c.HasPK2() && !c.HasSign1() && !c.HasSign2():
		state = StateInit
	case c.HasPK1() && c.HasPK2() && !c.HasSign1() && c.HasSign2():
		state = StateStep1
	case c.HasPK1() && c.HasPK2() && c.HasSign1() && c.HasSign2():
		state = StateComplete
	default:
		return fmt.Errorf("invalid challenge structure")
	}
	if err := checkStructure(c, state); err != nil {
		return err
	}
	c.State = state
	if state == StateInit {
		return nil
	}
	if bytes.Equal(c.PK1, c.PK2) {
		return fmt.Errorf("pk1 and pk2 must differ")
	}

	unsigned, err := SerializeUnsigned(c)
	if err != nil {
		return fmt.Errorf("failed to serialize for verification: %w", err)
	}

	id2, err := vaultysid.FromID(c.PK2, nil)
	if err != nil {
		return fmt.Errorf("invalid pk2: %w", err)
	}
	if err := id2.VerifyHandshake(unsigned, c.Sign2); err != nil {
		return fmt.Errorf("failed to verify sign2: %w", err)
	}

	if state == StateComplete {
		id1, err := vaultysid.FromID(c.PK1, nil)
		if err != nil {
			return fmt.Errorf("invalid pk1: %w", err)
		}
		if err := id1.VerifyHandshake(unsigned, c.Sign1); err != nil {
			return fmt.Errorf("failed to verify sign1: %w", err)
		}
	}
	return nil
}
