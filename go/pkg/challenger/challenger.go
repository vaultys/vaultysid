package challenger

import (
	"bytes"
	"fmt"

	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
	"github.com/vmihailenco/msgpack/v5"
)

// Challenger implements the handcheck protocol for mutual authentication
type Challenger struct {
	vaultysID *vaultysid.VaultysID
	state     *ChallengerState
	options   *ChallengerOptions
}

// NewChallenger creates a new Challenger instance
func NewChallenger(vid *vaultysid.VaultysID, opts *ChallengerOptions) *Challenger {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &Challenger{
		vaultysID: vid,
		options:   opts,
		state: &ChallengerState{
			VaultysID: vid,
			State:     StateUninitialized,
			Version:   opts.Version,
			Metadata:  make(map[string]string),
		},
	}
}

// New creates a new Challenger instance with default options (wrapper for compatibility)
func New(vid *vaultysid.VaultysID) *Challenger {
	return NewChallenger(vid, nil)
}

// Init initializes the challenge protocol
func (c *Challenger) Init(protocol, service string) (*Challenge, error) {
	if c.state.State != StateUninitialized {
		return nil, fmt.Errorf("challenger already initialized")
	}

	// Generate 16-byte nonce for init
	nonce, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	c.state.Protocol = protocol
	c.state.Service = service
	c.state.Nonce = nonce
	c.state.Timestamp = crypto.Now()
	c.state.State = StateInit

	// Create init challenge
	challenge := &Challenge{
		Version:   c.options.Version,
		Protocol:  protocol,
		Service:   service,
		Timestamp: uint64(c.state.Timestamp),
		PK1:       c.vaultysID.ToBytes(),
		Nonce:     nonce,
		Metadata: ChallengeMetadata{
			PK1: c.state.Metadata,
		},
		State: StateInit,
	}

	c.state.LastChallenge = challenge
	return challenge, nil
}

// Step1 processes the init message and returns step1 response
func (c *Challenger) Step1(initChallenge *Challenge) (*Challenge, error) {
	// Validate init challenge
	if initChallenge.State != StateInit {
		return nil, fmt.Errorf("invalid challenge state: expected INIT, got %d", initChallenge.State)
	}

	if !initChallenge.HasPK1() || len(initChallenge.Nonce) != 16 {
		return nil, fmt.Errorf("invalid init challenge: missing PK1 or invalid nonce")
	}

	// Check timestamp
	if err := c.validateTimestamp(int64(initChallenge.Timestamp)); err != nil {
		return nil, err
	}

	// Store remote info
	c.state.RemoteID = initChallenge.PK1
	c.state.RemoteNonce = initChallenge.Nonce
	c.state.Protocol = initChallenge.Protocol
	c.state.Service = initChallenge.Service
	c.state.Timestamp = int64(initChallenge.Timestamp)

	// Generate our 16-byte nonce
	ourNonce, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Combine nonces (remote first, then ours)
	combinedNonce := append(initChallenge.Nonce, ourNonce...)
	c.state.Nonce = combinedNonce

	// Create unsigned challenge for signing
	unsignedChallenge := &Challenge{
		Version:   initChallenge.Version,
		Protocol:  initChallenge.Protocol,
		Service:   initChallenge.Service,
		Timestamp: initChallenge.Timestamp,
		PK1:       initChallenge.PK1,
		PK2:       c.vaultysID.ToBytes(),
		Nonce:     combinedNonce,
		Metadata: ChallengeMetadata{
			PK1: make(map[string]string),
			PK2: make(map[string]string),
		},
	}

	// Sign the challenge
	challengeBytes, err := SerializeUnsigned(unsignedChallenge)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize challenge: %w", err)
	}

	var signature []byte
	if initChallenge.Version == ProtocolV0 {
		signature, err = c.vaultysID.SignChallengeV0(challengeBytes, c.vaultysID.ToBytes())
	} else {
		signature, err = c.vaultysID.SignChallenge(challengeBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to sign challenge: %w", err)
	}

	// Create step1 response
	step1 := &Challenge{
		Version:   initChallenge.Version,
		Protocol:  initChallenge.Protocol,
		Service:   initChallenge.Service,
		Timestamp: initChallenge.Timestamp,
		PK1:       initChallenge.PK1,
		PK2:       c.vaultysID.ToBytes(),
		Nonce:     combinedNonce,
		Sign2:     signature,
		Metadata: ChallengeMetadata{
			PK2: c.state.Metadata,
		},
		State: StateStep1,
	}

	c.state.State = StateStep1
	c.state.LastChallenge = step1
	return step1, nil
}

// Step2 processes the step1 message and returns the complete challenge
func (c *Challenger) Step2(step1Challenge *Challenge) (*Challenge, error) {
	// Validate step1 challenge
	if step1Challenge.State != StateStep1 {
		return nil, fmt.Errorf("invalid challenge state: expected STEP1, got %d", step1Challenge.State)
	}

	if !step1Challenge.HasPK2() || !step1Challenge.HasSign2() || len(step1Challenge.Nonce) != 32 {
		return nil, fmt.Errorf("invalid step1 challenge: missing fields")
	}

	// Verify we're the initiator
	if !bytes.Equal(step1Challenge.PK1, c.vaultysID.ToBytes()) {
		return nil, fmt.Errorf("PK1 mismatch: not our identity")
	}

	// Check that the first 16 bytes of nonce match our original nonce
	if !bytes.Equal(step1Challenge.Nonce[:16], c.state.Nonce) {
		return nil, fmt.Errorf("nonce mismatch")
	}

	// Verify the remote signature
	remoteID, err := vaultysid.FromID(step1Challenge.PK2, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote ID: %w", err)
	}

	unsignedChallenge := &Challenge{
		Version:   step1Challenge.Version,
		Protocol:  step1Challenge.Protocol,
		Service:   step1Challenge.Service,
		Timestamp: step1Challenge.Timestamp,
		PK1:       step1Challenge.PK1,
		PK2:       step1Challenge.PK2,
		Nonce:     step1Challenge.Nonce,
		Metadata: ChallengeMetadata{
			PK1: make(map[string]string),
			PK2: make(map[string]string),
		},
	}

	challengeBytes, err := SerializeUnsigned(unsignedChallenge)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize challenge: %w", err)
	}

	// Try v1 verification first, then v0 if it fails
	err = remoteID.VerifyChallenge(challengeBytes, step1Challenge.Sign2)
	if err != nil {
		// Try v0 verification
		err = remoteID.VerifyChallengeV0(challengeBytes, step1Challenge.Sign2, step1Challenge.PK2)
		if err != nil {
			return nil, fmt.Errorf("failed to verify remote signature: %w", err)
		}
	}

	// Sign our part
	var ourSignature []byte
	if step1Challenge.Version == ProtocolV0 {
		ourSignature, err = c.vaultysID.SignChallengeV0(challengeBytes, c.vaultysID.ToBytes())
	} else {
		ourSignature, err = c.vaultysID.SignChallenge(challengeBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to sign challenge: %w", err)
	}

	// Create complete challenge
	complete := &Challenge{
		Version:   step1Challenge.Version,
		Protocol:  step1Challenge.Protocol,
		Service:   step1Challenge.Service,
		Timestamp: step1Challenge.Timestamp,
		PK1:       step1Challenge.PK1,
		PK2:       step1Challenge.PK2,
		Nonce:     step1Challenge.Nonce,
		Sign1:     ourSignature,
		Sign2:     step1Challenge.Sign2,
		Metadata:  step1Challenge.Metadata,
		State:     StateComplete,
	}

	c.state.State = StateComplete
	c.state.RemoteID = step1Challenge.PK2
	c.state.LastChallenge = complete
	return complete, nil
}

// Finalize processes the complete challenge and finalizes the protocol
func (c *Challenger) Finalize(completeChallenge *Challenge) error {
	// Validate complete challenge
	if completeChallenge.State != StateComplete {
		return fmt.Errorf("invalid challenge state: expected COMPLETE, got %d", completeChallenge.State)
	}

	if !completeChallenge.HasPK1() || !completeChallenge.HasPK2() ||
		!completeChallenge.HasSign1() || !completeChallenge.HasSign2() {
		return fmt.Errorf("incomplete challenge: missing required fields")
	}

	// Verify we're the responder
	if !bytes.Equal(completeChallenge.PK2, c.vaultysID.ToBytes()) {
		return fmt.Errorf("PK2 mismatch: not our identity")
	}

	// Verify both signatures
	id1, err := vaultysid.FromID(completeChallenge.PK1, nil)
	if err != nil {
		return fmt.Errorf("failed to parse PK1: %w", err)
	}

	id2, err := vaultysid.FromID(completeChallenge.PK2, nil)
	if err != nil {
		return fmt.Errorf("failed to parse PK2: %w", err)
	}

	unsignedChallenge := &Challenge{
		Version:   completeChallenge.Version,
		Protocol:  completeChallenge.Protocol,
		Service:   completeChallenge.Service,
		Timestamp: completeChallenge.Timestamp,
		PK1:       completeChallenge.PK1,
		PK2:       completeChallenge.PK2,
		Nonce:     completeChallenge.Nonce,
		Metadata: ChallengeMetadata{
			PK1: make(map[string]string),
			PK2: make(map[string]string),
		},
	}

	challengeBytes, err := SerializeUnsigned(unsignedChallenge)
	if err != nil {
		return fmt.Errorf("failed to serialize challenge: %w", err)
	}

	// Verify PK1's signature
	err = id1.VerifyChallenge(challengeBytes, completeChallenge.Sign1)
	if err != nil {
		// Try v0 verification
		err = id1.VerifyChallengeV0(challengeBytes, completeChallenge.Sign1, completeChallenge.PK1)
		if err != nil {
			return fmt.Errorf("failed to verify PK1 signature: %w", err)
		}
	}

	// Verify PK2's signature (should be ours)
	err = id2.VerifyChallenge(challengeBytes, completeChallenge.Sign2)
	if err != nil {
		// Try v0 verification
		err = id2.VerifyChallengeV0(challengeBytes, completeChallenge.Sign2, completeChallenge.PK2)
		if err != nil {
			return fmt.Errorf("failed to verify PK2 signature: %w", err)
		}
	}

	c.state.State = StateComplete
	c.state.RemoteID = completeChallenge.PK1
	c.state.LastChallenge = completeChallenge
	return nil
}

// Process handles an incoming challenge and returns the appropriate response
func (c *Challenger) Process(incomingChallenge *Challenge) (*Challenge, error) {
	switch incomingChallenge.State {
	case StateInit:
		return c.Step1(incomingChallenge)
	case StateStep1:
		return c.Step2(incomingChallenge)
	case StateComplete:
		err := c.Finalize(incomingChallenge)
		if err != nil {
			return nil, err
		}
		return incomingChallenge, nil
	default:
		return nil, fmt.Errorf("invalid challenge state: %d", incomingChallenge.State)
	}
}

// GetState returns the current challenger state
func (c *Challenger) GetState() int {
	return c.state.State
}

// GetRemoteID returns the remote identity bytes
func (c *Challenger) GetRemoteID() []byte {
	return c.state.RemoteID
}

// GetRemoteVaultysID returns the remote VaultysID
func (c *Challenger) GetRemoteVaultysID() (*vaultysid.VaultysID, error) {
	if c.state.RemoteID == nil {
		return nil, fmt.Errorf("no remote ID available")
	}
	return vaultysid.FromID(c.state.RemoteID, nil)
}

// IsComplete returns true if the challenge protocol is complete
func (c *Challenger) IsComplete() bool {
	return c.state.State == StateComplete
}

// Reset resets the challenger to uninitialized state
func (c *Challenger) Reset() {
	c.state = &ChallengerState{
		VaultysID: c.vaultysID,
		State:     StateUninitialized,
		Version:   c.options.Version,
		Metadata:  make(map[string]string),
	}
}

// Accept accepts an incoming challenge and returns a response
func (c *Challenger) Accept(challengeBytes []byte) (*Challenge, error) {
	// Deserialize infers State from which fields are present (PK1/PK2/Sign1/Sign2/nonce
	// length) since State isn't part of the wire format (msgpack:"-"). A raw
	// msgpack.Unmarshal here would leave State at its zero value (StateInit) for
	// every message, mishandling step1/complete messages as init messages.
	challenge, err := Deserialize(challengeBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize challenge: %w", err)
	}

	var response *Challenge

	// Process based on challenge state
	switch challenge.State {
	case StateInit:
		// We're the responder, process init and return step1
		response, err = c.Step1(challenge)
		if err != nil {
			return nil, fmt.Errorf("failed to process init: %w", err)
		}
	case StateStep1:
		// We're the initiator, process step1 and return complete
		response, err = c.Step2(challenge)
		if err != nil {
			return nil, fmt.Errorf("failed to process step1: %w", err)
		}
	case StateComplete:
		// We're the responder, finalize the protocol
		if err := c.Finalize(challenge); err != nil {
			return nil, fmt.Errorf("failed to finalize: %w", err)
		}
		// Return nil for successful finalization
		return nil, nil
	default:
		return nil, fmt.Errorf("invalid challenge state: %d", challenge.State)
	}

	return response, nil
}

// SetMetadata sets metadata to include in challenges
func (c *Challenger) SetMetadata(key, value string) {
	c.state.Metadata[key] = value
}

// GetMetadata gets a metadata value
func (c *Challenger) GetMetadata(key string) (string, bool) {
	val, ok := c.state.Metadata[key]
	return val, ok
}

// validateTimestamp checks if the timestamp is within the allowed time window.
// Timestamps are Unix milliseconds, matching TS Challenger's use of Date.now()/liveliness.
func (c *Challenger) validateTimestamp(timestamp int64) error {
	now := crypto.Now()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}

	maxDiff := c.options.TimeWindow.Milliseconds()
	if diff > maxDiff {
		return fmt.Errorf("timestamp outside allowed window: %d ms", diff)
	}
	return nil
}

// Serialize serializes a challenge to bytes.
//
// This marshals the Challenge struct directly rather than building a
// map[string]interface{}: msgpack.Marshal on a map has no stable key
// order (Go map iteration is randomized per call), which produced
// non-reproducible wire bytes and could never byte-match TS's
// insertion-ordered serialize(). The Challenge struct's own msgpack
// tags already declare the correct field order and correct
// per-field omitempty (pk2/sign1/sign2), so marshaling it directly
// reproduces TS's exact field order and field set for every state
// (State/Error are tagged `msgpack:"-"` and excluded automatically).
func Serialize(challenge *Challenge) ([]byte, error) {
	return msgpack.Marshal(challenge)
}

// orderedChallengeData is used to ensure consistent field ordering in msgpack
// Fields must match TypeScript order: version, protocol, service, timestamp, pk1, pk2, nonce, metadata
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

// SerializeUnsigned serializes a challenge without signatures for signing
func SerializeUnsigned(challenge *Challenge) ([]byte, error) {
	// Ensure metadata is always initialized
	metadata := challenge.Metadata
	if metadata.PK1 == nil {
		metadata.PK1 = make(map[string]string)
	}
	if metadata.PK2 == nil {
		metadata.PK2 = make(map[string]string)
	}

	// Use ordered struct to match TypeScript field order exactly
	data := orderedChallengeData{
		Version:   challenge.Version,
		Protocol:  challenge.Protocol,
		Service:   challenge.Service,
		Timestamp: challenge.Timestamp,
		PK1:       challenge.PK1,
		PK2:       challenge.PK2,
		Nonce:     challenge.Nonce,
		Metadata:  metadata,
	}

	return msgpack.Marshal(data)
}

// Deserialize deserializes a challenge from bytes
func Deserialize(data []byte) (*Challenge, error) {
	var challenge Challenge
	if err := msgpack.Unmarshal(data, &challenge); err != nil {
		return nil, fmt.Errorf("failed to unmarshal challenge: %w", err)
	}

	// Validate and set state based on fields present
	if err := validateAndSetState(&challenge); err != nil {
		challenge.State = StateError
		challenge.Error = err.Error()
		return &challenge, err
	}

	return &challenge, nil
}

// validateAndSetState determines the state based on challenge fields
func validateAndSetState(c *Challenge) error {
	// Basic validation
	if c.Protocol == "" || c.Service == "" || c.Timestamp == 0 {
		return fmt.Errorf("missing required fields")
	}

	// Determine state based on fields
	if c.HasPK1() && !c.HasPK2() && !c.HasSign1() && !c.HasSign2() && len(c.Nonce) == 16 {
		c.State = StateInit
		return nil
	}

	if c.HasPK1() && c.HasPK2() && !c.HasSign1() && c.HasSign2() && len(c.Nonce) == 32 {
		c.State = StateStep1
		// Verify sign2
		id2, err := vaultysid.FromID(c.PK2, nil)
		if err != nil {
			return fmt.Errorf("invalid PK2: %w", err)
		}

		unsignedBytes, err := SerializeUnsigned(c)
		if err != nil {
			return fmt.Errorf("failed to serialize for verification: %w", err)
		}

		err = id2.VerifyChallenge(unsignedBytes, c.Sign2)
		if err != nil {
			// Try v0 verification
			err = id2.VerifyChallengeV0(unsignedBytes, c.Sign2, c.PK2)
			if err != nil {
				return fmt.Errorf("failed to verify sign2: %w", err)
			}
		}
		return nil
	}

	if c.HasPK1() && c.HasPK2() && c.HasSign1() && c.HasSign2() && len(c.Nonce) == 32 {
		c.State = StateComplete

		// Verify both signatures
		id1, err := vaultysid.FromID(c.PK1, nil)
		if err != nil {
			return fmt.Errorf("invalid PK1: %w", err)
		}

		id2, err := vaultysid.FromID(c.PK2, nil)
		if err != nil {
			return fmt.Errorf("invalid PK2: %w", err)
		}

		unsignedBytes, err := SerializeUnsigned(c)
		if err != nil {
			return fmt.Errorf("failed to serialize for verification: %w", err)
		}

		// Verify sign1
		err = id1.VerifyChallenge(unsignedBytes, c.Sign1)
		if err != nil {
			// Try v0 verification
			err = id1.VerifyChallengeV0(unsignedBytes, c.Sign1, c.PK1)
			if err != nil {
				return fmt.Errorf("failed to verify sign1: %w", err)
			}
		}

		// Verify sign2
		err = id2.VerifyChallenge(unsignedBytes, c.Sign2)
		if err != nil {
			// Try v0 verification
			err = id2.VerifyChallengeV0(unsignedBytes, c.Sign2, c.PK2)
			if err != nil {
				return fmt.Errorf("failed to verify sign2: %w", err)
			}
		}

		return nil
	}

	return fmt.Errorf("invalid challenge structure")
}
