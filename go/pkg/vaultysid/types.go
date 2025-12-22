package vaultysid

// IdentityType represents the type of identity
type IdentityType uint8

const (
	TypeMachine      IdentityType = 0
	TypePerson       IdentityType = 1
	TypeOrganization IdentityType = 2
	TypeFIDO2        IdentityType = 3
	TypeFIDO2PRF     IdentityType = 4
)

// KeyManager is the interface that all key management implementations must satisfy
type KeyManager interface {
	// Signing operations
	Sign(data []byte) ([]byte, error)
	Verify(data, signature []byte) error

	// Key access
	GetPublicKey() []byte
	GetCypherPublicKey() []byte

	// Cryptographic operations
	DiffieHellman(peerPublicKey []byte) ([]byte, error)
	HMAC(message string) ([]byte, error)

	// Serialization
	ToBytes() []byte
	GetSecret() ([]byte, error)

	// Metadata
	GetCapability() string
	GetAuthType() string
	GetEncType() string
	GetVersion() int
	SetVersion(version int) error
}

// KeyPair represents a public/private key pair
type KeyPair struct {
	PublicKey []byte
	SecretKey []byte
}

// ChallengeData represents the data structure for challenge-response protocol
type ChallengeData struct {
	Protocol  string `msgpack:"protocol"`
	Service   string `msgpack:"service"`
	Timestamp int64  `msgpack:"timestamp"`
	Nonce     []byte `msgpack:"nonce"`
	Version   int    `msgpack:"version"`
}

// SignedChallenge represents a signed challenge response
type SignedChallenge struct {
	Challenge ChallengeData `msgpack:"challenge"`
	Signature []byte        `msgpack:"signature"`
	PublicKey []byte        `msgpack:"publicKey"`
}

// IdentityMetadata contains optional metadata for an identity
type IdentityMetadata struct {
	Name        string            `msgpack:"name,omitempty"`
	Description string            `msgpack:"description,omitempty"`
	Created     int64             `msgpack:"created,omitempty"`
	Updated     int64             `msgpack:"updated,omitempty"`
	Tags        []string          `msgpack:"tags,omitempty"`
	Properties  map[string]string `msgpack:"properties,omitempty"`
}

// SerializedIdentity represents the complete serialized form of an identity
type SerializedIdentity struct {
	Type        IdentityType      `msgpack:"type"`
	KeyManager  []byte            `msgpack:"keyManager"`
	Certificate []byte            `msgpack:"certificate,omitempty"`
	Metadata    *IdentityMetadata `msgpack:"metadata,omitempty"`
}

// Constants for protocol versions
const (
	ProtocolV0 = 0
	ProtocolV1 = 1
)

// Constants for capability levels
const (
	CapabilityPrivate = "private"
	CapabilityPublic  = "public"
)

// IdentityTypeString returns the string representation of an IdentityType
func (t IdentityType) String() string {
	switch t {
	case TypeMachine:
		return "machine"
	case TypePerson:
		return "person"
	case TypeOrganization:
		return "organization"
	case TypeFIDO2:
		return "fido2"
	case TypeFIDO2PRF:
		return "fido2prf"
	default:
		return "unknown"
	}
}

// ParseIdentityType parses a string into an IdentityType
func ParseIdentityType(s string) (IdentityType, error) {
	switch s {
	case "machine":
		return TypeMachine, nil
	case "person":
		return TypePerson, nil
	case "organization":
		return TypeOrganization, nil
	case "fido2":
		return TypeFIDO2, nil
	case "fido2prf":
		return TypeFIDO2PRF, nil
	default:
		return 0, ErrInvalidIdentityType
	}
}

// IsValid checks if the IdentityType is valid
func (t IdentityType) IsValid() bool {
	return t <= TypeFIDO2PRF
}

// IsHardware returns true if the identity type represents hardware-backed identity
func (t IdentityType) IsHardware() bool {
	return t == TypeFIDO2 || t == TypeFIDO2PRF
}
