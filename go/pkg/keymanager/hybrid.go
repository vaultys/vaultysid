package keymanager

import (
	"crypto/ed25519"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/curve25519"
)

// HybridManager signs with Ed25519 and ML-DSA-87 together, paired with an
// X25519 encryption key, matching TS KeyManager/HybridManager.ts:
//
//	seed        = SHA-512(entropy)                      ; 64 bytes, exported as {v, alg: "hybrid", s}
//	signerSeed  = SHA-512(seed[0:32])
//	ML-DSA-87   = KeyGen(signerSeed[0:32])
//	Ed25519     = key of the 32-byte seed signerSeed[32:64]
//	X25519 sk   = seed[32:64]
//	public key  = Ed25519 pk (32) || ML-DSA-87 pk (2592)
//	signature   = sig_ed || ML-DSA-87.Sign(data || sig_ed)
//
// A signature verifies only if both parts verify.
type HybridManager struct {
	Version    int
	Capability string
	Entropy    []byte
	Seed       []byte
	// Signer.PublicKey is Ed25519 || ML-DSA-87; Signer.SecretKey is the
	// packed ML-DSA-87 private key.
	Signer KeyPair
	// edSeed is the 32-byte Ed25519 seed (signerSeed[32:64]).
	edSeed []byte
	Cypher KeyPair
	// pqKeys is set for post-quantum identities only (rfc/PQ-ENCRYPTION.md).
	pqKeys
}

// HybridPublicKeySize is the size of a hybrid signing public key.
const HybridPublicKeySize = ed25519.PublicKeySize + mldsa87.PublicKeySize // 2624

// hybridSecretExport matches TS HybridManager's SecretExport {v, alg, s}.
type hybridSecretExport struct {
	V   int    `msgpack:"v"`
	Alg string `msgpack:"alg"`
	S   []byte `msgpack:"s"`
}

func (m *HybridManager) GetAuthType() string { return "DilithiumEdDSAVerificationKey2025" }

func (m *HybridManager) GetEncType() string { return "X25519KeyAgreementKey2019" }

func (m *HybridManager) GetCapability() string { return m.Capability }

func deriveHybridFromSeed(km *HybridManager, seed []byte) error {
	if len(seed) != pqSeedSize {
		return fmt.Errorf("hybrid seed must be 64 bytes, got %d", len(seed))
	}
	signerSeed := crypto.Hash("sha512", seed[:32])
	defer crypto.SecureErase(signerSeed)

	var mldsaSeed [mldsa87.SeedSize]byte
	copy(mldsaSeed[:], signerSeed[:32])
	pqPub, pqPriv := mldsa87.NewKeyFromSeed(&mldsaSeed)
	crypto.SecureErase(mldsaSeed[:])
	packedPub, err := pqPub.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to pack ML-DSA public key: %w", err)
	}
	packedPriv, err := pqPriv.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to pack ML-DSA private key: %w", err)
	}

	edSeed := make([]byte, ed25519.SeedSize)
	copy(edSeed, signerSeed[32:64])
	edPub := ed25519.NewKeyFromSeed(edSeed).Public().(ed25519.PublicKey)

	cypherSecret := make([]byte, 32)
	copy(cypherSecret, seed[32:64])
	cypherPublic, err := curve25519.X25519(cypherSecret, curve25519.Basepoint)
	if err != nil {
		return err
	}

	publicKey := make([]byte, 0, HybridPublicKeySize)
	publicKey = append(publicKey, edPub...)
	publicKey = append(publicKey, packedPub...)
	km.Signer = KeyPair{PublicKey: publicKey, SecretKey: packedPriv}
	km.edSeed = edSeed
	km.Cypher = KeyPair{PublicKey: cypherPublic, SecretKey: cypherSecret}
	return nil
}

// CreateHybridFromEntropy creates a HybridManager from 32 bytes of entropy,
// matching TS HybridManager.createFromEntropy.
func CreateHybridFromEntropy(entropy []byte) (*HybridManager, error) {
	km := &HybridManager{Version: 1, Capability: "private", Entropy: entropy}
	km.Seed = crypto.Hash("sha512", entropy)
	if err := deriveHybridFromSeed(km, km.Seed); err != nil {
		return nil, err
	}
	return km, nil
}

// GenerateHybrid creates a HybridManager from fresh random entropy.
func GenerateHybrid() (*HybridManager, error) {
	entropy, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	return CreateHybridFromEntropy(entropy)
}

// HybridFromSecret restores a private HybridManager from {v, alg: "hybrid", s}.
func HybridFromSecret(secret []byte) (*HybridManager, error) {
	var data hybridSecretExport
	if err := msgpack.Unmarshal(secret, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal hybrid secret: %w", err)
	}
	if data.Alg != "hybrid" {
		return nil, fmt.Errorf("not a secret for hybrid cryptography")
	}
	if !validVersion(data.V) {
		return nil, fmt.Errorf("invalid hybrid secret: unsupported version %d", data.V)
	}
	km := &HybridManager{Version: data.V, Capability: "private", Seed: data.S}
	if err := deriveHybridFromSeed(km, data.S); err != nil {
		return nil, err
	}
	return km, nil
}

// HybridFromID restores a public-only HybridManager from {v, x, e}.
func HybridFromID(id []byte) (*HybridManager, error) {
	var data dataExport
	if err := msgpack.Unmarshal(id, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal hybrid id: %w", err)
	}
	if !validVersion(data.V) {
		return nil, fmt.Errorf("invalid hybrid id: unsupported version %d", data.V)
	}
	return hybridFromKeys(data.V, data.X, data.E)
}

func hybridFromKeys(version int, x, e []byte) (*HybridManager, error) {
	if len(x) != HybridPublicKeySize {
		return nil, fmt.Errorf("invalid hybrid id: signing key must be %d bytes, got %d", HybridPublicKeySize, len(x))
	}
	if len(e) != x25519KeySize {
		return nil, fmt.Errorf("invalid hybrid id: encryption key must be 32 bytes, got %d", len(e))
	}
	km := &HybridManager{Version: version, Capability: "public"}
	km.Signer = KeyPair{PublicKey: x}
	km.Cypher = KeyPair{PublicKey: e}
	return km, nil
}

// ToBytes encodes {v, x, e}, plus k for a post-quantum identity.
func (m *HybridManager) ToBytes() []byte {
	return encodeKeyManagerRecord(m.Version, m.Signer.PublicKey, m.Cypher.PublicKey, m.KEMPublicKey)
}

func (m *HybridManager) GetSecret() ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	return msgpack.Marshal(hybridSecretExport{V: m.Version, Alg: "hybrid", S: m.Seed})
}

// Sign returns sig_ed || ML-DSA-87.Sign(data || sig_ed), as TS HybridManager.
func (m *HybridManager) Sign(data []byte) ([]byte, error) {
	if m.Capability != "private" || len(m.edSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("no private key")
	}
	var priv mldsa87.PrivateKey
	if err := priv.UnmarshalBinary(m.Signer.SecretKey); err != nil {
		return nil, fmt.Errorf("failed to unpack ML-DSA private key: %w", err)
	}
	edSig := ed25519.Sign(ed25519.NewKeyFromSeed(m.edSeed), data)
	signed := make([]byte, 0, len(data)+len(edSig))
	signed = append(signed, data...)
	signed = append(signed, edSig...)
	pqSig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(&priv, signed, nil, true, pqSig); err != nil {
		return nil, fmt.Errorf("ML-DSA signing failed: %w", err)
	}
	return append(edSig, pqSig...), nil
}

// Verify requires both the Ed25519 and the ML-DSA-87 signature to verify.
func (m *HybridManager) Verify(data, signature []byte) error {
	if len(m.Signer.PublicKey) != HybridPublicKeySize {
		return fmt.Errorf("invalid public key")
	}
	if len(signature) != ed25519.SignatureSize+mldsa87.SignatureSize {
		return fmt.Errorf("invalid signature")
	}
	edSig, pqSig := signature[:ed25519.SignatureSize], signature[ed25519.SignatureSize:]
	if !ed25519.Verify(m.Signer.PublicKey[:ed25519.PublicKeySize], data, edSig) {
		return fmt.Errorf("invalid signature")
	}
	var pub mldsa87.PublicKey
	if err := pub.UnmarshalBinary(m.Signer.PublicKey[ed25519.PublicKeySize:]); err != nil {
		return fmt.Errorf("failed to unpack ML-DSA public key: %w", err)
	}
	signed := make([]byte, 0, len(data)+len(edSig))
	signed = append(signed, data...)
	signed = append(signed, edSig...)
	if !mldsa87.Verify(&pub, signed, nil, pqSig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (m *HybridManager) GetPublicKey() []byte { return m.Signer.PublicKey }

func (m *HybridManager) GetCypherPublicKey() []byte { return m.Cypher.PublicKey }

// GetCypherSecretKey returns the X25519 secret key.
func (m *HybridManager) GetCypherSecretKey() ([]byte, error) {
	return cypherSecret(m.Capability, m.Cypher)
}

// DiffieHellman returns the raw X25519 output, unhashed.
func (m *HybridManager) DiffieHellman(peerPublicKey []byte) ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	return curve25519.X25519(m.Cypher.SecretKey, peerPublicKey)
}

func (m *HybridManager) HMAC(message string) ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	key, err := m.pqKeys.hmacKey(m.Cypher.SecretKey)
	if err != nil {
		return nil, err
	}
	return crypto.HMAC("sha256", key, []byte("VaultysID/"+message+"/end")), nil
}

// GetSecretHash matches TS CypherManager.getSecretHash.
func (m *HybridManager) GetSecretHash(data []byte) ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	key, err := m.pqKeys.hmacKey(m.Cypher.SecretKey)
	if err != nil {
		return nil, err
	}
	return secretHash(data, key), nil
}

// EnablePostQuantum derives the ML-KEM-768 key pair and the PRF key from the
// seed (rfc/PQ-ENCRYPTION.md §3). Post-quantum identities only exist in version 1.
func (m *HybridManager) EnablePostQuantum() error {
	if m.Capability != "private" || len(m.Seed) != pqSeedSize {
		return fmt.Errorf("a seed is required to derive post-quantum keys")
	}
	if err := m.pqKeys.enable(m.Seed); err != nil {
		return err
	}
	m.Version = 1
	return nil
}

func (m *HybridManager) IsPostQuantum() bool { return m.pqKeys.isPostQuantum() }

func (m *HybridManager) GetKEMPublicKey() []byte { return m.KEMPublicKey }

// KEMDecapsulate decapsulates with the key re-derived from the seed.
func (m *HybridManager) KEMDecapsulate(ciphertext []byte) ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	return m.pqKeys.decapsulate(m.Seed, ciphertext)
}

func (m *HybridManager) GetVersion() int { return m.Version }

func (m *HybridManager) SetVersion(version int) error {
	if m.IsPostQuantum() {
		// post-quantum ids exist only in version 1 (TS toVersion is a no-op)
		return nil
	}
	if version != 0 && version != 1 {
		return fmt.Errorf("unsupported version: %d", version)
	}
	m.Version = version
	return nil
}

func (m *HybridManager) CleanSecureData() {
	m.pqKeys.clean()
	for _, b := range [][]byte{m.Cypher.SecretKey, m.Signer.SecretKey, m.edSeed, m.Seed, m.Entropy} {
		if b != nil {
			crypto.SecureErase(b)
		}
	}
	m.Cypher.SecretKey, m.Signer.SecretKey, m.edSeed, m.Seed, m.Entropy = nil, nil, nil, nil, nil
}

var (
	_ PostQuantumKeyManager = (*HybridManager)(nil)
	_ PostQuantumKeyManager = (*DilithiumManager)(nil)
	_ CypherSecretProvider  = (*HybridManager)(nil)
)
