package vaultysid

import "errors"

// Common errors for VaultysID operations
var (
	// Identity errors
	ErrInvalidIdentityType = errors.New("invalid identity type")
	ErrEmptyID             = errors.New("empty identity ID")
	ErrEmptySecret         = errors.New("empty secret")
	ErrInvalidIDLength     = errors.New("invalid ID length")
	ErrInvalidSecretLength = errors.New("invalid secret length")

	// Key manager errors
	ErrNoPrivateKey        = errors.New("no private key available")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrInvalidPublicKey    = errors.New("invalid public key")
	ErrKeyGenerationFailed = errors.New("key generation failed")

	// Entropy errors
	ErrInvalidEntropy     = errors.New("invalid entropy")
	ErrInvalidEntropySize = errors.New("entropy must be 32 bytes")

	// Certificate errors
	ErrNoCertificate      = errors.New("no certificate available")
	ErrInvalidCertificate = errors.New("invalid certificate")

	// Encoding errors
	ErrUnsupportedEncoding = errors.New("unsupported encoding")
	ErrDecodeFailed        = errors.New("failed to decode")
	ErrEncodeFailed        = errors.New("failed to encode")

	// Protocol errors
	ErrInvalidChallenge = errors.New("invalid challenge")
	ErrInvalidProtocol  = errors.New("invalid protocol")
	ErrProtocolMismatch = errors.New("protocol version mismatch")

	// FIDO2 errors
	ErrFIDO2NotImplemented = errors.New("FIDO2 not implemented in Go version")
	ErrFIDO2NotAvailable   = errors.New("FIDO2 not available in this environment")

	// Serialization errors
	ErrSerializationFailed   = errors.New("serialization failed")
	ErrDeserializationFailed = errors.New("deserialization failed")

	// Capability errors
	ErrInsufficientCapability = errors.New("insufficient capability for operation")
	ErrPublicOnlyOperation    = errors.New("operation requires private key capability")

	// Version errors
	ErrUnsupportedVersion = errors.New("unsupported protocol version")
	ErrVersionMismatch    = errors.New("version mismatch")
)
