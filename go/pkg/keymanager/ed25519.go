package keymanager

import (
	"crypto/ed25519"
	"fmt"

	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/curve25519"
)

type Ed25519Manager struct {
	Version    int
	Capability string
	Entropy    []byte
	Signer     KeyPair
	Cypher     KeyPair
}

type KeyPair struct {
	PublicKey []byte
	SecretKey []byte
}

type dataExport struct {
	V int    `msgpack:"v"`
	X []byte `msgpack:"x"`
	E []byte `msgpack:"e"`
}

// orderedMap creates a map that msgpack will encode in the correct order
func orderedMap(v uint8, x, e []byte) map[string]interface{} {
	// msgpack-go encodes map keys in sorted order
	// "e" < "v" < "x" alphabetically, but we need "v", "x", "e"
	// We'll use a custom type that preserves order
	return map[string]interface{}{
		"v": v,
		"x": x,
		"e": e,
	}
}

func (m *Ed25519Manager) GetAuthType() string {
	return "Ed25519VerificationKey2020"
}

func (m *Ed25519Manager) GetEncType() string {
	return "X25519KeyAgreementKey2019"
}

func (m *Ed25519Manager) GetCapability() string {
	return m.Capability
}

func CreateFromEntropyInternal(entropy []byte) (*Ed25519Manager, error) {
	km := &Ed25519Manager{
		Version:    1,
		Capability: "private",
		Entropy:    entropy,
	}

	seed := crypto.Hash("sha512", entropy)

	// Ed25519 from first 32 bytes
	privateKey := ed25519.NewKeyFromSeed(seed[:32])
	km.Signer = KeyPair{
		PublicKey: privateKey.Public().(ed25519.PublicKey),
		SecretKey: privateKey[:32],
	}

	// X25519 from second 32 bytes
	var cypherSecret [32]byte
	copy(cypherSecret[:], seed[32:64])
	cypherPublic, err := curve25519.X25519(cypherSecret[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	km.Cypher = KeyPair{
		PublicKey: cypherPublic,
		SecretKey: cypherSecret[:],
	}

	return km, nil
}

func GenerateInternal() (*Ed25519Manager, error) {
	entropy, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	return CreateFromEntropyInternal(entropy)
}

func (m *Ed25519Manager) ToBytes() []byte {
	// Match TypeScript's msgpack encoding exactly
	data := dataExport{
		V: int(m.Version),
		X: m.Signer.PublicKey,
		E: m.Cypher.PublicKey,
	}
	encoded, _ := msgpack.Marshal(data)
	return encoded
}

func (m *Ed25519Manager) GetSecret() ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	data := dataExport{
		V: int(m.Version),
		X: m.Signer.SecretKey,
		E: m.Cypher.SecretKey,
	}
	encoded, err := msgpack.Marshal(data)
	return encoded, err
}

// Ed25519 / X25519 key sizes used to validate untrusted encodings before
// slicing or handing them to crypto primitives (crypto/ed25519 panics on a
// public key of the wrong length).
const (
	ed25519PublicKeySize = ed25519.PublicKeySize // 32
	x25519KeySize        = 32
)

func validVersion(v int) bool { return v == 0 || v == 1 }

func FromSecretInternal(secret []byte) (*Ed25519Manager, error) {
	var data dataExport
	if err := msgpack.Unmarshal(secret, &data); err != nil {
		return nil, fmt.Errorf("invalid ed25519 secret: %w", err)
	}
	if !validVersion(data.V) {
		return nil, fmt.Errorf("invalid ed25519 secret: unsupported version %d", data.V)
	}
	// TS may store either the 32-byte seed or the 64-byte NaCl secret key
	// (seed || public key); only the seed is needed.
	if len(data.X) != ed25519.SeedSize && len(data.X) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 secret: signing key must be 32 or 64 bytes, got %d", len(data.X))
	}
	if len(data.E) != x25519KeySize {
		return nil, fmt.Errorf("invalid ed25519 secret: encryption key must be 32 bytes, got %d", len(data.E))
	}

	km := &Ed25519Manager{
		Version:    data.V,
		Capability: "private",
	}

	seed := append([]byte(nil), data.X[:ed25519.SeedSize]...)
	privateKey := ed25519.NewKeyFromSeed(seed)
	km.Signer = KeyPair{
		SecretKey: seed,
		PublicKey: privateKey.Public().(ed25519.PublicKey),
	}

	cypherSecret := append([]byte(nil), data.E...)
	cypherPublic, err := curve25519.X25519(cypherSecret, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	km.Cypher = KeyPair{
		PublicKey: cypherPublic,
		SecretKey: cypherSecret,
	}

	return km, nil
}

func FromIDInternal(id []byte) (*Ed25519Manager, error) {
	var data dataExport
	if err := msgpack.Unmarshal(id, &data); err != nil {
		return nil, fmt.Errorf("invalid ed25519 id: %w", err)
	}
	if !validVersion(data.V) {
		return nil, fmt.Errorf("invalid ed25519 id: unsupported version %d", data.V)
	}
	if len(data.X) != ed25519PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 id: signing key must be 32 bytes, got %d", len(data.X))
	}
	if len(data.E) != x25519KeySize {
		return nil, fmt.Errorf("invalid ed25519 id: encryption key must be 32 bytes, got %d", len(data.E))
	}

	km := &Ed25519Manager{
		Version:    data.V,
		Capability: "public",
	}
	km.Signer = KeyPair{
		PublicKey: append([]byte(nil), data.X...),
	}
	km.Cypher = KeyPair{
		PublicKey: append([]byte(nil), data.E...),
	}

	return km, nil
}

func (m *Ed25519Manager) Sign(data []byte) ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	if len(m.Signer.SecretKey) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid signing key")
	}
	privateKey := ed25519.NewKeyFromSeed(m.Signer.SecretKey)
	return ed25519.Sign(privateKey, data), nil
}

func (m *Ed25519Manager) Verify(data, signature []byte) error {
	// crypto/ed25519.Verify panics on a public key of the wrong length.
	if len(m.Signer.PublicKey) != ed25519PublicKeySize {
		return fmt.Errorf("invalid public key")
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature")
	}
	if !ed25519.Verify(m.Signer.PublicKey, data, signature) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (m *Ed25519Manager) GetPublicKey() []byte {
	return m.Signer.PublicKey
}

func (m *Ed25519Manager) GetCypherPublicKey() []byte {
	return m.Cypher.PublicKey
}

// DiffieHellman returns the raw X25519 scalar-mult output, matching TS's
// `cypher.diffieHellman` (KeyManager/CypherManager.ts getCypher()). It is
// intentionally unhashed here; VaultysID.PerformDiffieHellman is the layer
// that hashes it, matching TS's CypherManager.performDiffieHellman.
func (m *Ed25519Manager) DiffieHellman(peerPublicKey []byte) ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	shared, err := curve25519.X25519(m.Cypher.SecretKey, peerPublicKey)
	if err != nil {
		return nil, err
	}
	return shared, nil
}

func (m *Ed25519Manager) HMAC(message string) ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	data := []byte("VaultysID/" + message + "/end")
	return crypto.HMAC("sha256", m.Cypher.SecretKey, data), nil
}

func (m *Ed25519Manager) GetVersion() int {
	return m.Version
}

func (m *Ed25519Manager) SetVersion(version int) error {
	if version != 0 && version != 1 {
		return fmt.Errorf("unsupported version: %d", version)
	}
	m.Version = version
	return nil
}

func (m *Ed25519Manager) CleanSecureData() {
	if m.Cypher.SecretKey != nil {
		crypto.SecureErase(m.Cypher.SecretKey)
		m.Cypher.SecretKey = nil
	}
	if m.Signer.SecretKey != nil {
		crypto.SecureErase(m.Signer.SecretKey)
		m.Signer.SecretKey = nil
	}
	if m.Entropy != nil {
		crypto.SecureErase(m.Entropy)
		m.Entropy = nil
	}
}
