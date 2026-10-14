package challenger

import (
	"fmt"
	"sort"
	"time"

	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
	"github.com/vmihailenco/msgpack/v5"
)

// Protocol states
const (
	StateError         = -2
	StateUninitialized = -1
	StateInit          = 0
	StateStep1         = 1
	StateComplete      = 2
)

// ProtocolV1 is the only supported challenge version. Version 0 (and its
// fallback signature scheme) was removed in the security-v2 release; any
// message with another version is rejected.
const ProtocolV1 = 1

// Size of each party's nonce contribution.
const nonceHalfSize = 16

// Challenge represents the challenge-response protocol data.
//
// Field order matches the TypeScript reference wire format.
type Challenge struct {
	Version  uint8  `msgpack:"version"`
	Protocol string `msgpack:"protocol"`
	Service  string `msgpack:"service"`
	// Timestamp is uint64, not int64: vmihailenco/msgpack encodes int64
	// fields with the signed msgpack type (0xd3), while TS's
	// @msgpack/msgpack encodes the same non-negative Date.now() value with
	// the unsigned type (0xcf). Timestamps are never negative.
	Timestamp uint64            `msgpack:"timestamp"`
	PK1       []byte            `msgpack:"pk1,omitempty"`
	PK2       []byte            `msgpack:"pk2,omitempty"`
	Nonce     []byte            `msgpack:"nonce,omitempty"`
	Sign1     []byte            `msgpack:"sign1,omitempty"`
	Sign2     []byte            `msgpack:"sign2,omitempty"`
	Metadata  ChallengeMetadata `msgpack:"metadata"`
	State     int               `msgpack:"-"`
	Error     string            `msgpack:"-"`
}

// Result represents the result of a challenge operation
type Result struct {
	Challenge []byte                 `msgpack:"challenge"`
	Response  []byte                 `msgpack:"response,omitempty"`
	Metadata  map[string]interface{} `msgpack:"metadata,omitempty"`
	Success   bool                   `msgpack:"success"`
	State     int                    `msgpack:"state"`
}

// MetadataEntry is one key/value pair of a party's challenge metadata.
type MetadataEntry struct {
	Key   string
	Value string
}

// Metadata is an ordered string->string map.
//
// The handshake signature covers the msgpack encoding of the metadata, and
// the TypeScript reference encodes objects in insertion order (which, for a
// received message, is wire order). To reproduce the signed bytes exactly,
// Metadata therefore preserves entry order and distinguishes "absent" (nil)
// from "present but empty" (non-nil, zero length).
type Metadata []MetadataEntry

// NewMetadata builds a present Metadata from a map, with keys sorted so the
// encoding is deterministic. A nil or empty map yields a present, empty
// Metadata (encoded as {}), matching TS IdManager's default `{}`.
func NewMetadata(m map[string]string) Metadata {
	md := make(Metadata, 0, len(m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		md = append(md, MetadataEntry{Key: k, Value: m[k]})
	}
	return md
}

// Get returns the value for key.
func (md Metadata) Get(key string) (string, bool) {
	for _, e := range md {
		if e.Key == key {
			return e.Value, true
		}
	}
	return "", false
}

// ToMap returns the metadata as a map (nil if absent).
func (md Metadata) ToMap() map[string]string {
	if md == nil {
		return nil
	}
	m := make(map[string]string, len(md))
	for _, e := range md {
		m[e.Key] = e.Value
	}
	return m
}

// Equal reports whether two Metadata are identical, including presence and order.
func (md Metadata) Equal(other Metadata) bool {
	if (md == nil) != (other == nil) || len(md) != len(other) {
		return false
	}
	for i := range md {
		if md[i] != other[i] {
			return false
		}
	}
	return true
}

// Clone returns a deep copy preserving presence.
func (md Metadata) Clone() Metadata {
	if md == nil {
		return nil
	}
	return append(make(Metadata, 0, len(md)), md...)
}

// EncodeMsgpack encodes the metadata as a msgpack map in entry order.
func (md Metadata) EncodeMsgpack(enc *msgpack.Encoder) error {
	if md == nil {
		return enc.EncodeNil()
	}
	if err := enc.EncodeMapLen(len(md)); err != nil {
		return err
	}
	for _, e := range md {
		if err := enc.EncodeString(e.Key); err != nil {
			return err
		}
		if err := enc.EncodeString(e.Value); err != nil {
			return err
		}
	}
	return nil
}

// DecodeMsgpack decodes a msgpack map of strings, preserving wire order.
func (md *Metadata) DecodeMsgpack(dec *msgpack.Decoder) error {
	n, err := dec.DecodeMapLen()
	if err != nil {
		return err
	}
	if n < 0 {
		return fmt.Errorf("metadata must be a map")
	}
	out := make(Metadata, 0, n)
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		k, err := decodeStrictString(dec)
		if err != nil {
			return fmt.Errorf("metadata key: %w", err)
		}
		v, err := decodeStrictString(dec)
		if err != nil {
			return fmt.Errorf("metadata value: %w", err)
		}
		if _, dup := seen[k]; dup {
			return fmt.Errorf("duplicate metadata key %q", k)
		}
		seen[k] = struct{}{}
		out = append(out, MetadataEntry{Key: k, Value: v})
	}
	*md = out
	return nil
}

func decodeStrictString(dec *msgpack.Decoder) (string, error) {
	v, err := dec.DecodeInterface()
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("expected string, got %T", v)
	}
	return s, nil
}

// ChallengeMetadata contains each party's optional metadata. A nil field is
// absent from the encoding; a non-nil empty one is encoded as {}.
type ChallengeMetadata struct {
	PK1 Metadata
	PK2 Metadata
}

// EncodeMsgpack encodes {pk1?, pk2?} in that order.
func (cm ChallengeMetadata) EncodeMsgpack(enc *msgpack.Encoder) error {
	n := 0
	if cm.PK1 != nil {
		n++
	}
	if cm.PK2 != nil {
		n++
	}
	if err := enc.EncodeMapLen(n); err != nil {
		return err
	}
	if cm.PK1 != nil {
		if err := enc.EncodeString("pk1"); err != nil {
			return err
		}
		if err := cm.PK1.EncodeMsgpack(enc); err != nil {
			return err
		}
	}
	if cm.PK2 != nil {
		if err := enc.EncodeString("pk2"); err != nil {
			return err
		}
		if err := cm.PK2.EncodeMsgpack(enc); err != nil {
			return err
		}
	}
	return nil
}

// DecodeMsgpack strictly decodes {pk1?, pk2?}; pk1 must precede pk2 (the
// only order the canonical encoding produces) and no other key is allowed.
func (cm *ChallengeMetadata) DecodeMsgpack(dec *msgpack.Decoder) error {
	n, err := dec.DecodeMapLen()
	if err != nil {
		return err
	}
	if n < 0 {
		return fmt.Errorf("metadata must be a map")
	}
	var out ChallengeMetadata
	last := ""
	for i := 0; i < n; i++ {
		k, err := decodeStrictString(dec)
		if err != nil {
			return fmt.Errorf("metadata key: %w", err)
		}
		var md Metadata
		if err := md.DecodeMsgpack(dec); err != nil {
			return fmt.Errorf("metadata.%s: %w", k, err)
		}
		switch {
		case k == "pk1" && last == "":
			out.PK1 = md
		case k == "pk2" && (last == "" || last == "pk1"):
			out.PK2 = md
		default:
			return fmt.Errorf("unexpected or out-of-order metadata key %q", k)
		}
		last = k
	}
	*cm = out
	return nil
}

// Equal reports whether both parties' metadata are identical.
func (cm ChallengeMetadata) Equal(other ChallengeMetadata) bool {
	return cm.PK1.Equal(other.PK1) && cm.PK2.Equal(other.PK2)
}

// AcceptFunc is a consent callback. It is always given the REMOTE party's
// identity (pk1 when we are the responder, pk2 when we are the initiator)
// together with the protocol and service, and is called before we sign.
// Returning an error aborts the handshake.
type AcceptFunc func(remote *vaultysid.VaultysID, protocol, service string) error

// ChallengerOptions configures a Challenger.
type ChallengerOptions struct {
	// TimeWindow is the liveliness window for challenge timestamps
	// (default 60 seconds).
	TimeWindow time.Duration
	// Accept, if set, is consulted before signing (see AcceptFunc).
	Accept AcceptFunc
}

// DefaultOptions returns default challenger options.
func DefaultOptions() *ChallengerOptions {
	return &ChallengerOptions{
		TimeWindow: 60 * time.Second,
	}
}

// IsError returns true if the challenge is in error state
func (c *Challenge) IsError() bool {
	return c.State == StateError
}

// IsInit returns true if the challenge is in init state
func (c *Challenge) IsInit() bool {
	return c.State == StateInit
}

// IsStep1 returns true if the challenge is in step 1 state
func (c *Challenge) IsStep1() bool {
	return c.State == StateStep1
}

// IsComplete returns true if the challenge is complete
func (c *Challenge) IsComplete() bool {
	return c.State == StateComplete
}

// HasPK1 returns true if PK1 is present
func (c *Challenge) HasPK1() bool {
	return len(c.PK1) > 0
}

// HasPK2 returns true if PK2 is present
func (c *Challenge) HasPK2() bool {
	return len(c.PK2) > 0
}

// HasSign1 returns true if Sign1 is present
func (c *Challenge) HasSign1() bool {
	return len(c.Sign1) > 0
}

// HasSign2 returns true if Sign2 is present
func (c *Challenge) HasSign2() bool {
	return len(c.Sign2) > 0
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append(make([]byte, 0, len(b)), b...)
}

// Clone creates a deep copy of the challenge
func (c *Challenge) Clone() *Challenge {
	return &Challenge{
		Version:   c.Version,
		Protocol:  c.Protocol,
		Service:   c.Service,
		Timestamp: c.Timestamp,
		PK1:       cloneBytes(c.PK1),
		PK2:       cloneBytes(c.PK2),
		Nonce:     cloneBytes(c.Nonce),
		Sign1:     cloneBytes(c.Sign1),
		Sign2:     cloneBytes(c.Sign2),
		Metadata: ChallengeMetadata{
			PK1: c.Metadata.PK1.Clone(),
			PK2: c.Metadata.PK2.Clone(),
		},
		State: c.State,
		Error: c.Error,
	}
}
