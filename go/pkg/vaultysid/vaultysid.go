package vaultysid

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"github.com/vaultys/vaultysid/go/pkg/keymanager"
)

// Domain-separation prefixes (cross-language security spec §2). Every
// signature an identity produces is over SHA-256(prefix || data) with one of
// these prefixes, so a signature obtained through one API can never be
// replayed as a signature for another:
//
//   - SIGN_INCIPIT ("VAULTYS_SIGN"): SignChallenge/VerifyChallenge, used by
//     signFile and application challenges.
//   - RAW_INCIPIT ("VAULTYS_RAW"): the public raw Sign/Verify.
//   - HANDSHAKE_INCIPIT ("VAULTYS_HANDSHAKE_V1"): SignHandshake /
//     VerifyHandshake, used ONLY by the challenger (mutual-auth handshake).
var (
	SIGN_INCIPIT      = []byte("VAULTYS_SIGN")
	RAW_INCIPIT       = []byte("VAULTYS_RAW")
	HANDSHAKE_INCIPIT = []byte("VAULTYS_HANDSHAKE_V1")
)

// domainHash returns SHA-256(prefix || data) without aliasing either input.
func domainHash(prefix, data []byte) []byte {
	h := sha256.New()
	h.Write(prefix)
	h.Write(data)
	return h.Sum(nil)
}

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

// GenerateMachineAlg, GeneratePersonAlg, and GenerateOrganizationAlg create
// a new identity of the given algorithm ("ed25519" or "dilithium") with
// random entropy. See FromEntropyAlg.

func GenerateMachineAlg(alg string) (*VaultysID, error) {
	entropy, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate entropy: %w", err)
	}
	return FromEntropyAlg(entropy, TypeMachine, alg)
}

func GeneratePersonAlg(alg string) (*VaultysID, error) {
	entropy, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate entropy: %w", err)
	}
	return FromEntropyAlg(entropy, TypePerson, alg)
}

func GenerateOrganizationAlg(alg string) (*VaultysID, error) {
	entropy, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate entropy: %w", err)
	}
	return FromEntropyAlg(entropy, TypeOrganization, alg)
}

// FromEntropy creates a VaultysID from the given entropy bytes, using
// Ed25519. Use FromEntropyAlg to select a post-quantum algorithm.
func FromEntropy(entropy []byte, idType IdentityType) (*VaultysID, error) {
	return FromEntropyAlg(entropy, idType, "ed25519")
}

// FromEntropyAlg creates a VaultysID from the given entropy bytes using
// the named algorithm, matching TS VaultysId.fromEntropy's alg parameter:
// "ed25519" (default), "dilithium" (post-quantum ML-DSA-87), or
// "dilithium_ed25519" (hybrid -- not yet implemented in Go).
func FromEntropyAlg(entropy []byte, idType IdentityType, alg string) (*VaultysID, error) {
	if len(entropy) != 32 {
		return nil, fmt.Errorf("entropy must be 32 bytes, got %d", len(entropy))
	}

	var km KeyManager
	var err error

	switch alg {
	case "dilithium":
		km, err = keymanager.DilithiumCreateFromEntropy(entropy)
	case "dilithium_ed25519":
		return nil, fmt.Errorf("hybrid (dilithium_ed25519) identities are not yet implemented")
	case "", "ed25519":
		km, err = keymanager.CreateFromEntropy(entropy)
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", alg)
	}
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

	var km KeyManager
	var err error

	// Parse the key manager based on the identity type. Non-FIDO2 types are
	// further disambiguated by key-manager payload length, matching TS
	// VaultysId.fromId exactly: TS checks the *full* id length (2638
	// bytes = Dilithium, 2638+32 = Hybrid) including its own type byte, so
	// the length check on kmData (id with the type byte already stripped)
	// is one less: 2637 and 2637+32 respectively.
	kmData := id[1:]
	switch {
	case idType == TypeFIDO2 || idType == TypeFIDO2PRF:
		km, err = keymanager.FIDO2FromID(kmData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse FIDO2 key manager: %w", err)
		}
	case len(kmData) == 2637:
		km, err = keymanager.DilithiumFromID(kmData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Dilithium key manager: %w", err)
		}
	case len(kmData) == 2637+32:
		return nil, fmt.Errorf("hybrid (dilithium_ed25519) identities are not yet implemented")
	default:
		km, err = keymanager.FromID(kmData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key manager: %w", err)
		}
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

	var km KeyManager
	var err error

	// Parse the key manager based on the identity type. Non-FIDO2 types are
	// further disambiguated by secret payload length, matching TS
	// VaultysId.fromSecret exactly: TS checks the *full* secret length (73
	// bytes = Dilithium, 84 = Hybrid) including its own type byte, so the
	// length check on kmSecret (secret with the type byte already
	// stripped) is one less: 72 and 83 respectively.
	kmSecret := secret[1:]
	switch {
	case idType == TypeFIDO2 || idType == TypeFIDO2PRF:
		km, err = keymanager.FIDO2FromSecret(kmSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to create FIDO2 key manager from secret: %w", err)
		}
	case len(kmSecret) == 72:
		km, err = keymanager.DilithiumFromSecret(kmSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to create Dilithium key manager from secret: %w", err)
		}
	case len(kmSecret) == 83:
		return nil, fmt.Errorf("hybrid (dilithium_ed25519) identities are not yet implemented")
	default:
		km, err = keymanager.FromSecret(kmSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to create key manager from secret: %w", err)
		}
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

// Sign signs SHA-256("VAULTYS_RAW" || data). It never produces a raw
// key-manager signature, so it cannot be abused as a signing oracle for
// handshakes or challenges.
func (v *VaultysID) Sign(data []byte) ([]byte, error) {
	return v.KeyManager.Sign(domainHash(RAW_INCIPIT, data))
}

// Verify verifies a signature produced by Sign.
func (v *VaultysID) Verify(data, signature []byte) error {
	return v.KeyManager.Verify(domainHash(RAW_INCIPIT, data), signature)
}

// SignChallenge signs SHA-256("VAULTYS_SIGN" || challenge).
func (v *VaultysID) SignChallenge(challenge []byte) ([]byte, error) {
	return v.KeyManager.Sign(domainHash(SIGN_INCIPIT, challenge))
}

// VerifyChallenge verifies a signature produced by SignChallenge.
func (v *VaultysID) VerifyChallenge(challenge []byte, signature []byte) error {
	return v.KeyManager.Verify(domainHash(SIGN_INCIPIT, challenge), signature)
}

// SignHandshake signs SHA-256("VAULTYS_HANDSHAKE_V1" || unsignedChallenge).
// It must only be called by the challenger on the canonical unsigned
// challenge bytes it has validated itself.
func (v *VaultysID) SignHandshake(unsignedChallenge []byte) ([]byte, error) {
	return v.KeyManager.Sign(domainHash(HANDSHAKE_INCIPIT, unsignedChallenge))
}

// VerifyHandshake verifies a signature produced by SignHandshake.
func (v *VaultysID) VerifyHandshake(unsignedChallenge []byte, signature []byte) error {
	return v.KeyManager.Verify(domainHash(HANDSHAKE_INCIPIT, unsignedChallenge), signature)
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

// HMAC computes an HMAC-SHA256 of the input using the KeyManager's implementation
// This ensures consistency with TypeScript which wraps the message with "VaultysID/" prefix and "/end" suffix
func (v *VaultysID) HMAC(input string) ([]byte, error) {
	return v.KeyManager.HMAC(input)
}

// GetCypherPublicKey returns the cipher public key from the key manager
func (v *VaultysID) GetCypherPublicKey() []byte {
	return v.KeyManager.GetCypherPublicKey()
}

// DiffieHellman performs a Diffie-Hellman key exchange with the peer's public key
// This delegates to the KeyManager's DiffieHellman implementation
func (v *VaultysID) DiffieHellman(peerPublicKey []byte) ([]byte, error) {
	return v.KeyManager.DiffieHellman(peerPublicKey)
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

// Cryptographic operations

// PerformDiffieHellman performs a Diffie-Hellman key exchange with another VaultysID
// and hashes the raw scalar-mult output, matching TS CypherManager.performDiffieHellman.
// KeyManager.DiffieHellman itself stays unhashed (matches TS's low-level cypher.diffieHellman).
func (v *VaultysID) PerformDiffieHellman(peer *VaultysID) ([]byte, error) {
	if v.KeyManager.GetCapability() != "private" {
		return nil, fmt.Errorf("no private key available")
	}

	if peer == nil {
		return nil, fmt.Errorf("peer is nil")
	}

	peerPublicKey := peer.KeyManager.GetCypherPublicKey()
	if len(peerPublicKey) == 0 {
		return nil, fmt.Errorf("peer has no cypher public key")
	}

	shared, err := v.KeyManager.DiffieHellman(peerPublicKey)
	if err != nil {
		return nil, err
	}
	defer crypto.SecureErase(shared)

	return crypto.Hash("sha256", shared), nil
}

// DiffieHellman performs a Diffie-Hellman key exchange between two VaultysIDs
// Static method that tries with both identities to find one with private key
func DiffieHellman(id1, id2 *VaultysID) ([]byte, error) {
	// Try with id1 as the private key holder
	secret, err := id1.PerformDiffieHellman(id2)
	if err == nil {
		return secret, nil
	}

	// If that fails, try with id2 as the private key holder
	return id2.PerformDiffieHellman(id1)
}

// dhiesFor builds a DHIES v2 context from this identity's X25519 keypair.
func (v *VaultysID) dhiesFor() (*keymanager.DHIES, error) {
	if v.KeyManager.GetCapability() != "private" {
		return nil, fmt.Errorf("no private key available")
	}
	provider, ok := v.KeyManager.(keymanager.CypherSecretProvider)
	if !ok {
		return nil, fmt.Errorf("DHIES is not supported for this key manager")
	}
	sk, err := provider.GetCypherSecretKey()
	if err != nil {
		return nil, err
	}
	return keymanager.NewDHIESFromKeys(sk, v.KeyManager.GetCypherPublicKey())
}

// DHIESEncrypt encrypts plaintext to recipient with DHIES v2 (spec §3),
// authenticated as coming from this identity.
func (v *VaultysID) DHIESEncrypt(plaintext []byte, recipient *VaultysID) ([]byte, error) {
	if recipient == nil {
		return nil, fmt.Errorf("recipient is nil")
	}
	d, err := v.dhiesFor()
	if err != nil {
		return nil, err
	}
	return d.Encrypt(recipient.KeyManager.GetCypherPublicKey(), plaintext)
}

// DHIESDecrypt decrypts a DHIES v2 ciphertext addressed to this identity and
// verifies it was produced by sender.
func (v *VaultysID) DHIESDecrypt(ciphertext []byte, sender *VaultysID) ([]byte, error) {
	if sender == nil {
		return nil, fmt.Errorf("sender is nil")
	}
	d, err := v.dhiesFor()
	if err != nil {
		return nil, err
	}
	return d.Decrypt(ciphertext, sender.KeyManager.GetCypherPublicKey())
}

// GetOTP generates a one-time password based on the provided data
// This uses the identity's secret for OTP generation
func (v *VaultysID) GetOTP(data []byte) (string, error) {
	if v.KeyManager.GetCapability() != "private" {
		return "", fmt.Errorf("no private key available")
	}

	// TODO: Implement TOTP/HOTP generation using the identity's secret
	// This would derive an OTP secret from the identity and use standard OTP algorithms
	return "", fmt.Errorf("OTP generation not yet implemented")
}

// GetOTPHMAC generates an HMAC-based OTP
// This uses HMAC with the identity's secret for OTP generation
func (v *VaultysID) GetOTPHMAC(secret string) (string, error) {
	if v.KeyManager.GetCapability() != "private" {
		return "", fmt.Errorf("no private key available")
	}

	// TODO: Implement HMAC-based OTP using the identity's secret
	// This would use the KeyManager's HMAC capability with OTP algorithms
	return "", fmt.Errorf("OTP HMAC not yet implemented")
}
