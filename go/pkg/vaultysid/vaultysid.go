package vaultysid

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/vaultys/vaultysid-go/pkg/crypto"
	"github.com/vaultys/vaultysid-go/pkg/keymanager"
)

// SIGN_INCIPIT is the prefix used for challenge signing
var SIGN_INCIPIT = []byte("VAULTYS_SIGN")

// VaultysID represents a decentralized identity
type VaultysID struct {
	Type        IdentityType
	KeyManager  KeyManager
	Certificate []byte
}

// Generate functions for different identity types

// GenerateMachine creates a new machine identity with random entropy
func GenerateMachine() (*VaultysID, error) {
	entropy, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate entropy: %w", err)
	}
	return FromEntropy(entropy, TypeMachine)
}

// GeneratePerson creates a new person identity with random entropy
func GeneratePerson() (*VaultysID, error) {
	entropy, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate entropy: %w", err)
	}
	return FromEntropy(entropy, TypePerson)
}

// GenerateOrganization creates a new organization identity with random entropy
func GenerateOrganization() (*VaultysID, error) {
	entropy, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate entropy: %w", err)
	}
	return FromEntropy(entropy, TypeOrganization)
}

// FromEntropy creates a VaultysID from the given entropy bytes
func FromEntropy(entropy []byte, idType IdentityType) (*VaultysID, error) {
	if len(entropy) != 32 {
		return nil, fmt.Errorf("entropy must be 32 bytes, got %d", len(entropy))
	}

	km, err := keymanager.CreateFromEntropy(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to create key manager: %w", err)
	}

	return &VaultysID{
		Type:       idType,
		KeyManager: km,
	}, nil
}

// MachineFromEntropy creates a machine identity from entropy
func MachineFromEntropy(entropy []byte) (*VaultysID, error) {
	return FromEntropy(entropy, TypeMachine)
}

// PersonFromEntropy creates a person identity from entropy
func PersonFromEntropy(entropy []byte) (*VaultysID, error) {
	return FromEntropy(entropy, TypePerson)
}

// OrganizationFromEntropy creates an organization identity from entropy
func OrganizationFromEntropy(entropy []byte) (*VaultysID, error) {
	return FromEntropy(entropy, TypeOrganization)
}

// FromID deserializes a VaultysID from its byte representation
func FromID(id []byte, certificate []byte) (*VaultysID, error) {
	if len(id) == 0 {
		return nil, fmt.Errorf("empty id")
	}

	idType := IdentityType(id[0])

	// Validate identity type
	if idType > TypeFIDO2PRF {
		return nil, fmt.Errorf("invalid identity type: %d", idType)
	}

	// Skip FIDO2 types for now (not implemented in Go)
	if idType == TypeFIDO2 || idType == TypeFIDO2PRF {
		return nil, fmt.Errorf("FIDO2 types not implemented in Go version")
	}

	// Parse the key manager based on the remaining bytes
	km, err := keymanager.FromID(id[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to parse key manager: %w", err)
	}

	return &VaultysID{
		Type:        idType,
		KeyManager:  km,
		Certificate: certificate,
	}, nil
}

// FromIDString deserializes a VaultysID from a hex or base64 encoded string
func FromIDString(idStr string, encoding string, certificate []byte) (*VaultysID, error) {
	var id []byte
	var err error

	switch encoding {
	case "hex":
		id, err = hex.DecodeString(idStr)
	case "base64":
		id, err = base64.StdEncoding.DecodeString(idStr)
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to decode id string: %w", err)
	}

	return FromID(id, certificate)
}

// FromSecret creates a VaultysID from a secret key
func FromSecret(secret []byte) (*VaultysID, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("empty secret")
	}

	idType := IdentityType(secret[0])

	// Validate identity type
	if idType > TypeFIDO2PRF {
		return nil, fmt.Errorf("invalid identity type: %d", idType)
	}

	// Skip FIDO2 types for now
	if idType == TypeFIDO2 || idType == TypeFIDO2PRF {
		return nil, fmt.Errorf("FIDO2 types not implemented in Go version")
	}

	km, err := keymanager.FromSecret(secret[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to create key manager from secret: %w", err)
	}

	return &VaultysID{
		Type:       idType,
		KeyManager: km,
	}, nil
}

// FromSecretString creates a VaultysID from a hex or base64 encoded secret string
func FromSecretString(secretStr string, encoding string) (*VaultysID, error) {
	var secret []byte
	var err error

	switch encoding {
	case "hex":
		secret, err = hex.DecodeString(secretStr)
	case "base64":
		secret, err = base64.StdEncoding.DecodeString(secretStr)
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to decode secret string: %w", err)
	}

	return FromSecret(secret)
}

// Serialization methods

// ID returns the public identity bytes (type + key manager public data)
func (v *VaultysID) ID() []byte {
	return v.ToBytes()
}

// ToBytes serializes the VaultysID to bytes (public representation)
func (v *VaultysID) ToBytes() []byte {
	result := []byte{byte(v.Type)}
	return append(result, v.KeyManager.ToBytes()...)
}

// ToString serializes the VaultysID to a hex or base64 encoded string
func (v *VaultysID) ToString(encoding string) (string, error) {
	bytes := v.ToBytes()

	switch encoding {
	case "hex":
		return hex.EncodeToString(bytes), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(bytes), nil
	default:
		return "", fmt.Errorf("unsupported encoding: %s", encoding)
	}
}

// GetSecret returns the secret key bytes (type + key manager secret data)
func (v *VaultysID) GetSecret() ([]byte, error) {
	secret, err := v.KeyManager.GetSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to get secret from key manager: %w", err)
	}

	result := []byte{byte(v.Type)}
	return append(result, secret...), nil
}

// GetSecretString returns the secret key as a hex or base64 encoded string
func (v *VaultysID) GetSecretString(encoding string) (string, error) {
	secret, err := v.GetSecret()
	if err != nil {
		return "", err
	}

	switch encoding {
	case "hex":
		return hex.EncodeToString(secret), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(secret), nil
	default:
		return "", fmt.Errorf("unsupported encoding: %s", encoding)
	}
}

// DID returns the decentralized identifier for this identity
func (v *VaultysID) DID() string {
	// Match TypeScript: type byte + SHA224 hash of the keyManager.id (which is ToBytes())
	kmBytes := v.KeyManager.ToBytes()
	hash := sha256.Sum224(kmBytes)

	// Concatenate type byte with hash
	combined := append([]byte{byte(v.Type)}, hash[:]...)
	fp := hex.EncodeToString(combined)

	// Format: did:vaultys:{first 40 hex chars}
	return fmt.Sprintf("did:vaultys:%s", fp[:40])
}

// Signing and verification

// Sign signs the given data with the identity's private key
func (v *VaultysID) Sign(data []byte) ([]byte, error) {
	return v.KeyManager.Sign(data)
}

// Verify verifies a signature against the given data
func (v *VaultysID) Verify(data, signature []byte) error {
	return v.KeyManager.Verify(data, signature)
}

// SignChallenge signs a challenge with the proper protocol prefix
func (v *VaultysID) SignChallenge(challenge []byte) ([]byte, error) {
	// Hash the challenge with the sign incipit
	toHash := append(SIGN_INCIPIT, challenge...)
	hashed := crypto.Hash("sha256", toHash)

	return v.Sign(hashed)
}

// VerifyChallenge verifies a challenge signature
func (v *VaultysID) VerifyChallenge(challenge []byte, signature []byte) error {
	// Hash the challenge with the sign incipit
	toHash := append(SIGN_INCIPIT, challenge...)
	hashed := crypto.Hash("sha256", toHash)

	return v.Verify(hashed, signature)
}

// SignChallengeV0 signs a challenge using the v0 protocol (for backward compatibility)
func (v *VaultysID) SignChallengeV0(challenge []byte, oldID []byte) ([]byte, error) {
	// v0 protocol: hash(oldID + challenge)
	toHash := append(oldID, challenge...)
	hashed := crypto.Hash("sha256", toHash)

	return v.Sign(hashed)
}

// VerifyChallengeV0 verifies a v0 challenge signature
func (v *VaultysID) VerifyChallengeV0(challenge []byte, signature []byte, oldID []byte) error {
	// v0 protocol: hash(oldID + challenge)
	toHash := append(oldID, challenge...)
	hashed := crypto.Hash("sha256", toHash)

	return v.Verify(hashed, signature)
}

// Identity type checking methods

// IsMachine returns true if this is a machine identity
func (v *VaultysID) IsMachine() bool {
	return v.Type == TypeMachine
}

// IsPerson returns true if this is a person identity
func (v *VaultysID) IsPerson() bool {
	return v.Type == TypePerson
}

// IsOrganization returns true if this is an organization identity
func (v *VaultysID) IsOrganization() bool {
	return v.Type == TypeOrganization
}

// IsHardware returns true if this is a hardware-backed identity (FIDO2)
func (v *VaultysID) IsHardware() bool {
	return v.Type == TypeFIDO2 || v.Type == TypeFIDO2PRF
}

// GetType returns the identity type as a string
func (v *VaultysID) GetType() string {
	switch v.Type {
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

// Certificate management

// GetCertificate returns the certificate if present
func (v *VaultysID) GetCertificate() []byte {
	return v.Certificate
}

// SetCertificate sets the certificate
func (v *VaultysID) SetCertificate(cert []byte) {
	v.Certificate = cert
}

// HasCertificate returns true if the identity has a certificate
func (v *VaultysID) HasCertificate() bool {
	return len(v.Certificate) > 0
}

// Capability checking

// IsPrivate returns true if the identity has private key capabilities
func (v *VaultysID) IsPrivate() bool {
	return v.KeyManager.GetCapability() == "private"
}

// IsPublic returns true if the identity only has public key capabilities
func (v *VaultysID) IsPublic() bool {
	return v.KeyManager.GetCapability() == "public"
}

// GetCapability returns the capability level of the identity
func (v *VaultysID) GetCapability() string {
	return v.KeyManager.GetCapability()
}

// Key management

// GetPublicKey returns the signing public key
func (v *VaultysID) GetPublicKey() []byte {
	return v.KeyManager.GetPublicKey()
}

// GetCypherPublicKey returns the encryption public key
func (v *VaultysID) GetCypherPublicKey() []byte {
	return v.KeyManager.GetCypherPublicKey()
}

// Cryptographic operations

// DiffieHellman performs a Diffie-Hellman key exchange
func (v *VaultysID) DiffieHellman(peerPublicKey []byte) ([]byte, error) {
	return v.KeyManager.DiffieHellman(peerPublicKey)
}

// HMAC computes an HMAC of the given message
func (v *VaultysID) HMAC(message string) ([]byte, error) {
	return v.KeyManager.HMAC(message)
}

// Equals checks if two VaultysIDs are equal (same public keys and type)
func (v *VaultysID) Equals(other *VaultysID) bool {
	if v.Type != other.Type {
		return false
	}

	// Compare public keys
	if !bytes.Equal(v.GetPublicKey(), other.GetPublicKey()) {
		return false
	}

	if !bytes.Equal(v.GetCypherPublicKey(), other.GetCypherPublicKey()) {
		return false
	}

	return true
}

// Clone creates a deep copy of the VaultysID
func (v *VaultysID) Clone() *VaultysID {
	clone := &VaultysID{
		Type:       v.Type,
		KeyManager: v.KeyManager, // Note: KeyManager is not deep copied
	}

	if v.Certificate != nil {
		clone.Certificate = make([]byte, len(v.Certificate))
		copy(clone.Certificate, v.Certificate)
	}

	return clone
}

// Version management

// GetVersion returns the key manager version
func (v *VaultysID) GetVersion() int {
	return v.KeyManager.GetVersion()
}

// ToVersion sets the key manager version (for compatibility)
func (v *VaultysID) ToVersion(version int) error {
	return v.KeyManager.SetVersion(version)
}

// String returns a human-readable representation of the identity
func (v *VaultysID) String() string {
	return fmt.Sprintf("VaultysID{type=%s, did=%s, capability=%s}",
		v.GetType(), v.DID(), v.GetCapability())
}
