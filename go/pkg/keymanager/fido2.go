package keymanager

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/fxamacker/cbor/v2"
	vaultyscrypto "github.com/vaultys/vaultysid/go/pkg/crypto"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/curve25519"
)

// FIDO2Manager handles FIDO2/WebAuthn key operations
type FIDO2Manager struct {
	Version    int
	Capability string
	FID        []byte  // FIDO2 credential ID
	CKey       []byte  // COSE public key
	Transports int     // Bitmask of authenticator transports
	AuthType   string  // Verification key type
	Signer     KeyPair // Public key for verification
	Cypher     KeyPair // X25519 key for encryption

	// Optional relying-party policy enforced by Verify. When set, every
	// assertion must match: ExpectedRPIDHash is compared to authData[0:32]
	// (SHA-256 of the RP ID) and ExpectedOrigin to clientData.origin.
	// RequireUserVerification makes Verify demand the UV flag, not just UP.
	ExpectedRPIDHash        []byte
	ExpectedOrigin          string
	RequireUserVerification bool
}

// WebAuthn authenticator-data flag bits.
const (
	fido2FlagUP = 0x01 // user present
	fido2FlagUV = 0x04 // user verified
)

// FIDO2Signature represents a FIDO2 signature with authenticator data
type FIDO2Signature struct {
	S []byte `msgpack:"s"` // Signature
	C []byte `msgpack:"c"` // Client data JSON
	A []byte `msgpack:"a"` // Authenticator data
}

// ExportFIDO2Data represents the serialized FIDO2 data
type ExportFIDO2Data struct {
	V interface{} `msgpack:"v,omitempty"` // Version (can be various int types)
	F []byte      `msgpack:"f"`           // FID (credential ID)
	T interface{} `msgpack:"t"`           // Transports (can be various int types)
	C []byte      `msgpack:"c"`           // COSE key
	E []byte      `msgpack:"e"`           // Encryption public/secret key
}

// ExportFIDO2ID represents the public ID format
type ExportFIDO2ID struct {
	V interface{} `msgpack:"v,omitempty"` // Version (can be various int types)
	C []byte      `msgpack:"c"`           // COSE key
	E []byte      `msgpack:"e"`           // Encryption public key
}

// COSEKey represents a COSE key structure
type COSEKey map[int]interface{}

// Transport lookup table
var transportLookup = map[string]int{
	"usb":        1,
	"nfc":        2,
	"ble":        4,
	"internal":   8,
	"hybrid":     16,
	"smart-card": 32,
}

// COSE algorithm constants
const (
	COSEAlgEdDSA = -8 // EdDSA (Ed25519)
	COSEAlgES256 = -7 // ECDSA with SHA-256
	COSECrvP256  = 1  // P-256 curve
	COSEKtyEC2   = 2  // EC2 key type
	COSEKtyOKP   = 1  // OKP key type (for EdDSA)
)

// GetAuthType returns the authentication type
func (m *FIDO2Manager) GetAuthType() string {
	return m.AuthType
}

// GetEncType returns the encryption type
func (m *FIDO2Manager) GetEncType() string {
	return "X25519KeyAgreementKey2019"
}

// GetCapability returns the capability (public/private)
func (m *FIDO2Manager) GetCapability() string {
	return m.Capability
}

// GetVersion returns the version
func (m *FIDO2Manager) GetVersion() int {
	return m.Version
}

// SetVersion sets the version
func (m *FIDO2Manager) SetVersion(version int) error {
	if version != 0 && version != 1 {
		return fmt.Errorf("unsupported version: %d", version)
	}
	m.Version = version
	return nil
}

// getAuthTypeFromCKey determines the auth type from COSE key
func getAuthTypeFromCKey(ckey []byte) (string, error) {
	var key COSEKey
	if err := cbor.Unmarshal(ckey, &key); err != nil {
		return "", fmt.Errorf("failed to decode COSE key: %w", err)
	}

	kty, ok := key[1].(uint64)
	if !ok {
		if ktyInt, ok := key[1].(int64); ok {
			kty = uint64(ktyInt)
		} else {
			return "Unknown", nil
		}
	}

	switch kty {
	case uint64(COSEKtyOKP):
		return "Ed25519VerificationKey2020", nil
	case uint64(COSEKtyEC2):
		return "P256VerificationKey2020", nil
	default:
		return "Unknown", nil
	}
}

// getSignerFromCKey extracts the public key from COSE key
func getSignerFromCKey(ckey []byte) (KeyPair, error) {
	var key COSEKey
	if err := cbor.Unmarshal(ckey, &key); err != nil {
		return KeyPair{}, fmt.Errorf("failed to decode COSE key: %w", err)
	}

	var publicKey []byte

	// Get algorithm
	alg, ok := key[3].(int64)
	if !ok {
		if algUint, ok := key[3].(uint64); ok {
			alg = int64(algUint)
		} else {
			return KeyPair{}, fmt.Errorf("missing or invalid algorithm in COSE key")
		}
	}

	// Helper function to extract bytes from COSE key value
	extractBytes := func(v interface{}) ([]byte, error) {
		switch val := v.(type) {
		case []byte:
			return val, nil
		case cbor.Tag:
			// Handle CBOR tags (e.g., tag 64 for byte strings)
			if content, ok := val.Content.([]byte); ok {
				return content, nil
			}
			return nil, fmt.Errorf("unexpected tag content type: %T", val.Content)
		default:
			return nil, fmt.Errorf("unexpected value type: %T", v)
		}
	}

	switch alg {
	case COSEAlgES256: // P-256
		// Get X coordinate
		xVal, ok := key[-2]
		if !ok {
			return KeyPair{}, fmt.Errorf("missing X coordinate in P-256 key")
		}
		xBytes, err := extractBytes(xVal)
		if err != nil {
			return KeyPair{}, fmt.Errorf("invalid X coordinate: %w", err)
		}

		// Get Y coordinate
		yVal, ok := key[-3]
		if !ok {
			return KeyPair{}, fmt.Errorf("missing Y coordinate in P-256 key")
		}
		yBytes, err := extractBytes(yVal)
		if err != nil {
			return KeyPair{}, fmt.Errorf("invalid Y coordinate: %w", err)
		}

		if len(xBytes) != 32 || len(yBytes) != 32 {
			return KeyPair{}, fmt.Errorf("invalid P-256 key coordinates")
		}
		// Uncompressed point format: 0x04 || X || Y
		publicKey = make([]byte, 65)
		publicKey[0] = 0x04
		copy(publicKey[1:33], xBytes)
		copy(publicKey[33:65], yBytes)
		if _, err := ecdh.P256().NewPublicKey(publicKey); err != nil {
			return KeyPair{}, fmt.Errorf("invalid P-256 public key: %w", err)
		}
	case COSEAlgEdDSA: // Ed25519
		// Get X coordinate (public key for EdDSA)
		xVal, ok := key[-2]
		if !ok {
			return KeyPair{}, fmt.Errorf("missing public key in Ed25519 key")
		}
		xBytes, err := extractBytes(xVal)
		if err != nil {
			return KeyPair{}, fmt.Errorf("invalid Ed25519 public key: %w", err)
		}
		if len(xBytes) != 32 {
			return KeyPair{}, fmt.Errorf("invalid Ed25519 key length: got %d, want 32", len(xBytes))
		}
		publicKey = append([]byte(nil), xBytes...)
	default:
		return KeyPair{}, fmt.Errorf("unsupported algorithm: %d", alg)
	}

	return KeyPair{PublicKey: publicKey}, nil
}

// FIDO2ManagerFromSecret creates a FIDO2Manager from a secret
func FIDO2ManagerFromSecret(secret []byte) (*FIDO2Manager, error) {
	var data ExportFIDO2Data
	if err := msgpack.Unmarshal(secret, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret: %w", err)
	}

	// Convert version from interface{} to int
	version := 0
	if data.V != nil {
		version = toInt(data.V)
	}

	// Convert transports from interface{} to int
	transports := 0
	if data.T != nil {
		transports = toInt(data.T)
	}

	authType, err := getAuthTypeFromCKey(data.C)
	if err != nil {
		return nil, err
	}

	signer, err := getSignerFromCKey(data.C)
	if err != nil {
		return nil, err
	}

	if len(data.E) != x25519KeySize {
		return nil, fmt.Errorf("invalid FIDO2 secret: encryption key must be 32 bytes, got %d", len(data.E))
	}

	// Reconstruct X25519 keys from secret key
	cypherPublic, err := curve25519.X25519(data.E, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to compute public key: %w", err)
	}

	m := &FIDO2Manager{
		Version:    version,
		Capability: "private",
		FID:        data.F,
		CKey:       data.C,
		Transports: transports,
		AuthType:   authType,
		Signer:     signer,
		Cypher: KeyPair{
			PublicKey: cypherPublic,
			SecretKey: data.E,
		},
	}

	if m.Transports == 0 {
		m.Transports = 15 // Default to USB|NFC|BLE|Internal
	}

	return m, nil
}

// FIDO2ManagerFromID creates a FIDO2Manager from a public ID
func FIDO2ManagerFromID(id []byte) (*FIDO2Manager, error) {
	var data ExportFIDO2ID
	if err := msgpack.Unmarshal(id, &data); err != nil {
		// Try v0 format (not implemented for brevity)
		return nil, fmt.Errorf("failed to unmarshal ID: %w", err)
	}

	// Convert version from interface{} to int
	version := 0
	if data.V != nil {
		version = toInt(data.V)
	}

	authType, err := getAuthTypeFromCKey(data.C)
	if err != nil {
		return nil, err
	}

	signer, err := getSignerFromCKey(data.C)
	if err != nil {
		return nil, err
	}

	if len(data.E) != x25519KeySize {
		return nil, fmt.Errorf("invalid FIDO2 id: encryption key must be 32 bytes, got %d", len(data.E))
	}

	m := &FIDO2Manager{
		Version:    version,
		Capability: "public",
		CKey:       data.C,
		AuthType:   authType,
		Signer:     signer,
		Cypher: KeyPair{
			PublicKey: data.E,
		},
	}

	return m, nil
}

// ToBytes returns the public ID representation
func (m *FIDO2Manager) ToBytes() []byte {
	data := ExportFIDO2ID{
		V: m.Version,
		C: m.CKey,
		E: m.Cypher.PublicKey,
	}
	encoded, _ := msgpack.Marshal(data)
	return encoded
}

// GetSecret returns the private secret representation
func (m *FIDO2Manager) GetSecret() ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}

	data := ExportFIDO2Data{
		V: m.Version,
		F: m.FID,
		T: m.Transports,
		C: m.CKey,
		E: m.Cypher.SecretKey,
	}
	encoded, err := msgpack.Marshal(data)
	return encoded, err
}

// Sign is not implemented as it requires browser WebAuthn
func (m *FIDO2Manager) Sign(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("FIDO2 signing requires browser WebAuthn API")
}

// Verify verifies a FIDO2 signature
func (m *FIDO2Manager) Verify(data, signature []byte) error {
	return m.VerifyWithUserVerification(data, signature, false)
}

// fido2ClientData is the subset of CollectedClientData that Verify checks.
type fido2ClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// VerifyWithUserVerification verifies a FIDO2 assertion over data.
//
// It requires: clientData.type == "webauthn.get"; clientData.challenge ==
// base64url(SHA-256(data)); the UP flag; the UV flag when userVerification
// (or m.RequireUserVerification) is set; authData rpIdHash ==
// m.ExpectedRPIDHash and clientData.origin == m.ExpectedOrigin when those
// are configured; and a valid signature over authData || SHA-256(clientDataJSON).
func (m *FIDO2Manager) VerifyWithUserVerification(data, signature []byte, userVerification bool) error {
	var sig FIDO2Signature
	if err := msgpack.Unmarshal(signature, &sig); err != nil {
		return fmt.Errorf("failed to unmarshal signature: %w", err)
	}

	var clientData fido2ClientData
	if err := json.Unmarshal(sig.C, &clientData); err != nil {
		return fmt.Errorf("invalid client data: %w", err)
	}
	if clientData.Type != "webauthn.get" {
		return fmt.Errorf("invalid client data type %q", clientData.Type)
	}
	if m.ExpectedOrigin != "" && clientData.Origin != m.ExpectedOrigin {
		return fmt.Errorf("origin mismatch")
	}

	// Verify challenge matches
	challenge := vaultyscrypto.Hash("sha256", data)
	if !verifyChallenge(clientData.Challenge, challenge) {
		return fmt.Errorf("challenge mismatch")
	}

	// Verify the signature using the authenticator data and client data
	return m.verifySignature(sig.A, sig.C, sig.S, userVerification || m.RequireUserVerification)
}

// verifyChallenge checks if the base64url challenge from client data matches
func verifyChallenge(challengeStr string, expectedChallenge []byte) bool {
	// Accept both padded and unpadded base64url (and, for TS compatibility,
	// standard base64).
	challengeStr = strings.TrimRight(challengeStr, "=")
	challengeStr = strings.ReplaceAll(challengeStr, "+", "-")
	challengeStr = strings.ReplaceAll(challengeStr, "/", "_")

	decodedChallenge, err := base64.RawURLEncoding.DecodeString(challengeStr)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(decodedChallenge, expectedChallenge) == 1
}

// verifySignature verifies the FIDO2 signature
func (m *FIDO2Manager) verifySignature(authData, clientDataJSON, signature []byte, userVerification bool) error {
	if len(authData) < 37 {
		return fmt.Errorf("invalid authenticator data")
	}

	if m.ExpectedRPIDHash != nil && subtle.ConstantTimeCompare(authData[:32], m.ExpectedRPIDHash) != 1 {
		return fmt.Errorf("rpIdHash mismatch")
	}

	flags := authData[32]
	if flags&fido2FlagUP == 0 {
		return fmt.Errorf("user presence flag not set")
	}
	if userVerification && flags&fido2FlagUV == 0 {
		return fmt.Errorf("user verification required but not performed")
	}

	// Create the signed data: authData || sha256(clientDataJSON)
	clientDataHash := sha256.Sum256(clientDataJSON)
	signedData := make([]byte, 0, len(authData)+len(clientDataHash))
	signedData = append(signedData, authData...)
	signedData = append(signedData, clientDataHash[:]...)

	// Verify based on key type
	var key COSEKey
	if err := cbor.Unmarshal(m.CKey, &key); err != nil {
		return fmt.Errorf("failed to decode COSE key: %w", err)
	}

	// Get algorithm
	alg, ok := key[3].(int64)
	if !ok {
		if algUint, ok := key[3].(uint64); ok {
			alg = int64(algUint)
		} else {
			return fmt.Errorf("missing or invalid algorithm in COSE key")
		}
	}

	switch alg {
	case COSEAlgEdDSA: // Ed25519
		if len(m.Signer.PublicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
			return fmt.Errorf("Ed25519 signature verification failed")
		}
		if !ed25519.Verify(m.Signer.PublicKey, signedData, signature) {
			return fmt.Errorf("Ed25519 signature verification failed")
		}
	case COSEAlgES256: // P-256
		if !verifyP256Signature(m.Signer.PublicKey, signedData, signature) {
			return fmt.Errorf("P-256 signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported algorithm: %d", alg)
	}

	return nil
}

// verifyP256Signature verifies a P-256 ECDSA signature
func verifyP256Signature(publicKeyBytes, data, signature []byte) bool {
	if len(publicKeyBytes) != 65 || publicKeyBytes[0] != 0x04 {
		return false
	}

	// Parse public key
	x := new(big.Int).SetBytes(publicKeyBytes[1:33])
	y := new(big.Int).SetBytes(publicKeyBytes[33:65])
	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Hash the data
	hash := sha256.Sum256(data)

	if len(signature) == 64 {
		// Raw format (r||s), each component is 32 bytes
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		return ecdsa.Verify(publicKey, hash[:], r, s)
	}
	// Strict ASN.1 DER
	return ecdsa.VerifyASN1(publicKey, hash[:], signature)
}

// GetPublicKey returns the signing public key
func (m *FIDO2Manager) GetPublicKey() []byte {
	return m.Signer.PublicKey
}

// GetCypherPublicKey returns the encryption public key
func (m *FIDO2Manager) GetCypherPublicKey() []byte {
	return m.Cypher.PublicKey
}

// DiffieHellman performs ECDH key agreement
// DiffieHellman returns the raw X25519 scalar-mult output, matching TS's
// `cypher.diffieHellman`. It is intentionally unhashed here; VaultysID.PerformDiffieHellman
// is the layer that hashes it, matching TS's CypherManager.performDiffieHellman.
func (m *FIDO2Manager) DiffieHellman(peerPublicKey []byte) ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	shared, err := curve25519.X25519(m.Cypher.SecretKey, peerPublicKey)
	if err != nil {
		return nil, err
	}
	return shared, nil
}

// HMAC computes an HMAC
func (m *FIDO2Manager) HMAC(message string) ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	data := []byte("VaultysID/" + message + "/end")
	return vaultyscrypto.HMAC("sha256", m.Cypher.SecretKey, data), nil
}

// GetTransports returns the list of authenticator transports
func (m *FIDO2Manager) GetTransports() []string {
	var transports []string
	for name, bit := range transportLookup {
		if m.Transports&bit != 0 {
			transports = append(transports, name)
		}
	}
	return transports
}

// SetTransports sets the authenticator transports from a list
func (m *FIDO2Manager) SetTransports(transports []string) {
	m.Transports = 0
	for _, t := range transports {
		if bit, ok := transportLookup[t]; ok {
			m.Transports |= bit
		}
	}
}

// toInt converts various numeric types to int
func toInt(v interface{}) int {
	switch val := v.(type) {
	case int:
		return val
	case int8:
		return int(val)
	case int16:
		return int(val)
	case int32:
		return int(val)
	case int64:
		return int(val)
	case uint:
		return int(val)
	case uint8:
		return int(val)
	case uint16:
		return int(val)
	case uint32:
		return int(val)
	case uint64:
		return int(val)
	case float32:
		return int(val)
	case float64:
		return int(val)
	default:
		return 0
	}
}
