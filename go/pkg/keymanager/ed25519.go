package keymanager

import (
	"crypto/ed25519"
	"fmt"

	"github.com/vaultys/vaultysid-go/pkg/crypto"
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

func FromSecretInternal(secret []byte) (*Ed25519Manager, error) {
	var data dataExport
	if err := msgpack.Unmarshal(secret, &data); err != nil {
		return nil, err
	}

	km := &Ed25519Manager{
		Version:    int(data.V),
		Capability: "private",
	}

	// Reconstruct Ed25519 keys
	privateKey := ed25519.NewKeyFromSeed(data.X[:32])
	km.Signer = KeyPair{
		SecretKey: data.X[:32],
		PublicKey: privateKey.Public().(ed25519.PublicKey),
	}

	// Reconstruct X25519 keys
	cypherPublic, err := curve25519.X25519(data.E, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	km.Cypher = KeyPair{
		PublicKey: cypherPublic,
		SecretKey: data.E,
	}

	return km, nil
}

func FromIDInternal(id []byte) (*Ed25519Manager, error) {
	var data dataExport
	if err := msgpack.Unmarshal(id, &data); err != nil {
		return nil, err
	}

	km := &Ed25519Manager{
		Version:    int(data.V),
		Capability: "public",
	}
	km.Signer = KeyPair{
		PublicKey: data.X,
	}
	km.Cypher = KeyPair{
		PublicKey: data.E,
	}

	return km, nil
}

func (m *Ed25519Manager) Sign(data []byte) ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	privateKey := ed25519.NewKeyFromSeed(m.Signer.SecretKey)
	return ed25519.Sign(privateKey, data), nil
}

func (m *Ed25519Manager) Verify(data, signature []byte) error {
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
