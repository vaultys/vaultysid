package challenger

import (
	"time"
)

// Protocol states
const (
	StateError         = -2
	StateUninitialized = -1
	StateInit          = 0
	StateStep1         = 1
	StateComplete      = 2
)

// Protocol versions
const (
	ProtocolV0 = 0
	ProtocolV1 = 1
)

// Challenge represents the challenge-response protocol data
type Challenge struct {
	Version   uint8             `msgpack:"version"`
	Protocol  string            `msgpack:"protocol"`
	Service   string            `msgpack:"service"`
	Timestamp int64             `msgpack:"timestamp"`
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

// ChallengeMetadata contains optional metadata for the challenge
type ChallengeMetadata struct {
	PK1 map[string]string `msgpack:"pk1,omitempty"`
	PK2 map[string]string `msgpack:"pk2,omitempty"`
}

// ChallengerState represents the internal state of a challenger
type ChallengerState struct {
	VaultysID     interface{} // Will be *vaultysid.VaultysID but avoiding circular import
	Protocol      string
	Service       string
	Timestamp     int64
	Nonce         []byte
	RemoteID      []byte
	RemoteNonce   []byte
	State         int
	Version       uint8
	Metadata      map[string]string
	LastChallenge *Challenge
}

// Options for creating a new Challenger
type ChallengerOptions struct {
	Version         uint8
	TimeWindow      time.Duration // Default 60 seconds
	MetadataHandler func(map[string]string) error
}

// DefaultOptions returns default challenger options.
// Version defaults to 0 to match TS Challenger's `version: 0 | 1 = 0`.
func DefaultOptions() *ChallengerOptions {
	return &ChallengerOptions{
		Version:    ProtocolV0,
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

// Clone creates a deep copy of the challenge
func (c *Challenge) Clone() *Challenge {
	clone := &Challenge{
		Version:   c.Version,
		Protocol:  c.Protocol,
		Service:   c.Service,
		Timestamp: c.Timestamp,
		State:     c.State,
		Error:     c.Error,
		Metadata: ChallengeMetadata{
			PK1: make(map[string]string),
			PK2: make(map[string]string),
		},
	}

	// Copy byte slices
	if c.PK1 != nil {
		clone.PK1 = make([]byte, len(c.PK1))
		copy(clone.PK1, c.PK1)
	}
	if c.PK2 != nil {
		clone.PK2 = make([]byte, len(c.PK2))
		copy(clone.PK2, c.PK2)
	}
	if c.Nonce != nil {
		clone.Nonce = make([]byte, len(c.Nonce))
		copy(clone.Nonce, c.Nonce)
	}
	if c.Sign1 != nil {
		clone.Sign1 = make([]byte, len(c.Sign1))
		copy(clone.Sign1, c.Sign1)
	}
	if c.Sign2 != nil {
		clone.Sign2 = make([]byte, len(c.Sign2))
		copy(clone.Sign2, c.Sign2)
	}

	// Copy metadata maps
	for k, v := range c.Metadata.PK1 {
		clone.Metadata.PK1[k] = v
	}
	for k, v := range c.Metadata.PK2 {
		clone.Metadata.PK2[k] = v
	}

	return clone
}
