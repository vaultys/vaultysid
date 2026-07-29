package keymanager

import (
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/curve25519"
)

// DilithiumManager implements post-quantum signing paired with an X25519
// encryption key, matching TS KeyManager/DilithiumManager.ts and
// pqCrypto.ts.
//
// The signature algorithm is ML-DSA-87 (FIPS 204, the finalized NIST
// standard formerly known as Dilithium5/Level 5). TS uses
// @noble/post-quantum's ml_dsa87; Go uses
// github.com/cloudflare/circl/sign/mldsa/mldsa87. Both implement the same
// standard and are cross-compatible: FIPS 204 key generation from a seed
// is fully deterministic and specified by the standard, so
// mldsa87.NewKeyFromSeed produces byte-identical public keys to
// ml_dsa87.keygen for the same seed (verified against real TS output --
// see go/test/compatibility), and signatures produced by either
// implementation verify under the other.
type DilithiumManager struct {
	Version    int
	Capability string
	Entropy    []byte
	// Seed is SHA-512(Entropy). Seed[:32] is the ML-DSA key-generation
	// seed; Seed[32:64] is used directly as the X25519 secret scalar,
	// matching TS's nacl.box.keyPair.fromSecretKey(seed.slice(32, 64)).
	Seed   []byte
	Signer KeyPair
	Cypher KeyPair
}

// dilithiumSecretExport matches TS DilithiumManager's SecretExport type
// exactly: {v: version, s: 64-byte seed}. This is NOT the same shape as
// Ed25519Manager's secret (which stores both raw sub-keys under x/e);
// Dilithium's secret is just the seed, since both sub-keys are
// deterministically re-derived from it.
type dilithiumSecretExport struct {
	V int    `msgpack:"v"`
	S []byte `msgpack:"s"`
}

func (m *DilithiumManager) GetAuthType() string {
	return "DilithiumVerificationKey2025"
}

func (m *DilithiumManager) GetEncType() string {
	return "X25519KeyAgreementKey2019"
}

func (m *DilithiumManager) GetCapability() string {
	return m.Capability
}

// deriveDilithiumFromSeed reconstructs the ML-DSA and X25519 keypairs from
// a 64-byte seed. Shared by CreateDilithiumFromEntropyInternal (fresh
// entropy) and FromSecretDilithiumInternal (stored secret).
func deriveDilithiumFromSeed(seed []byte) (signer, cypher KeyPair, err error) {
	if len(seed) != 64 {
		return KeyPair{}, KeyPair{}, fmt.Errorf("dilithium seed must be 64 bytes, got %d", len(seed))
	}

	var mldsaSeed [mldsa87.SeedSize]byte
	copy(mldsaSeed[:], seed[:32])
	pub, priv := mldsa87.NewKeyFromSeed(&mldsaSeed)

	packedPub, err := pub.MarshalBinary()
	if err != nil {
		return KeyPair{}, KeyPair{}, fmt.Errorf("failed to pack ML-DSA public key: %w", err)
	}
	packedPriv, err := priv.MarshalBinary()
	if err != nil {
		return KeyPair{}, KeyPair{}, fmt.Errorf("failed to pack ML-DSA private key: %w", err)
	}

	var cypherSecret [32]byte
	copy(cypherSecret[:], seed[32:64])
	cypherPublic, err := curve25519.X25519(cypherSecret[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, KeyPair{}, err
	}

	return KeyPair{PublicKey: packedPub, SecretKey: packedPriv},
		KeyPair{PublicKey: cypherPublic, SecretKey: cypherSecret[:]},
		nil
}

// CreateDilithiumFromEntropyInternal creates a DilithiumManager from 32
// bytes of entropy, matching TS DilithiumManager.createFromEntropy.
func CreateDilithiumFromEntropyInternal(entropy []byte) (*DilithiumManager, error) {
	km := &DilithiumManager{
		Version:    1,
		Capability: "private",
		Entropy:    entropy,
	}

	km.Seed = crypto.Hash("sha512", entropy)

	signer, cypher, err := deriveDilithiumFromSeed(km.Seed)
	if err != nil {
		return nil, err
	}
	km.Signer = signer
	km.Cypher = cypher

	return km, nil
}

// GenerateDilithiumInternal creates a DilithiumManager from fresh random
// entropy, matching TS DilithiumManager.generate.
func GenerateDilithiumInternal() (*DilithiumManager, error) {
	entropy, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	return CreateDilithiumFromEntropyInternal(entropy)
}

// ToBytes reuses Ed25519Manager's dataExport{v,x,e} struct: both managers
// export the identical {version, signer public key, cypher public key}
// shape, and TS's DilithiumManager.id encodes to the same field names.
func (m *DilithiumManager) ToBytes() []byte {
	data := dataExport{
		V: m.Version,
		X: m.Signer.PublicKey,
		E: m.Cypher.PublicKey,
	}
	encoded, _ := msgpack.Marshal(data)
	return encoded
}

func (m *DilithiumManager) GetSecret() ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	data := dilithiumSecretExport{
		V: m.Version,
		S: m.Seed,
	}
	return msgpack.Marshal(data)
}

// FromSecretDilithiumInternal reconstructs a private DilithiumManager from
// its exported secret (the 64-byte seed, msgpack-wrapped), matching TS
// DilithiumManager.fromSecret.
func FromSecretDilithiumInternal(secret []byte) (*DilithiumManager, error) {
	var data dilithiumSecretExport
	if err := msgpack.Unmarshal(secret, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal dilithium secret: %w", err)
	}

	km := &DilithiumManager{
		Version:    data.V,
		Capability: "private",
		Seed:       data.S,
	}

	signer, cypher, err := deriveDilithiumFromSeed(data.S)
	if err != nil {
		return nil, err
	}
	km.Signer = signer
	km.Cypher = cypher

	return km, nil
}

// FromIDDilithiumInternal reconstructs a public-only DilithiumManager from
// its id bytes, matching TS DilithiumManager.fromId.
func FromIDDilithiumInternal(id []byte) (*DilithiumManager, error) {
	var data dataExport
	if err := msgpack.Unmarshal(id, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal dilithium id: %w", err)
	}

	km := &DilithiumManager{
		Version:    data.V,
		Capability: "public",
	}
	km.Signer = KeyPair{PublicKey: data.X}
	km.Cypher = KeyPair{PublicKey: data.E}

	return km, nil
}

// Sign matches TS DilithiumManager.getSigner()/pqCrypto.signDilithium:
// ml_dsa87.sign with randomized (hedged) signing, no context string. The
// caller (VaultysID.SignChallenge) is responsible for the
// SHA-256("VAULTYS_SIGN" || data) domain-separation hash applied
// uniformly across all key manager types -- Sign itself just signs
// whatever bytes it's given.
func (m *DilithiumManager) Sign(data []byte) ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	var priv mldsa87.PrivateKey
	if err := priv.UnmarshalBinary(m.Signer.SecretKey); err != nil {
		return nil, fmt.Errorf("failed to unpack ML-DSA private key: %w", err)
	}
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(&priv, data, nil, true, sig); err != nil {
		return nil, fmt.Errorf("ML-DSA signing failed: %w", err)
	}
	return sig, nil
}

// Verify matches TS DilithiumManager.verify/pqCrypto.verifyDilithium.
func (m *DilithiumManager) Verify(data, signature []byte) error {
	var pub mldsa87.PublicKey
	if err := pub.UnmarshalBinary(m.Signer.PublicKey); err != nil {
		return fmt.Errorf("failed to unpack ML-DSA public key: %w", err)
	}
	if !mldsa87.Verify(&pub, data, nil, signature) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (m *DilithiumManager) GetPublicKey() []byte {
	return m.Signer.PublicKey
}

func (m *DilithiumManager) GetCypherPublicKey() []byte {
	return m.Cypher.PublicKey
}

// DiffieHellman returns the raw X25519 scalar-mult output, unhashed (see
// Ed25519Manager.DiffieHellman for why).
func (m *DilithiumManager) DiffieHellman(peerPublicKey []byte) ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	return curve25519.X25519(m.Cypher.SecretKey, peerPublicKey)
}

func (m *DilithiumManager) HMAC(message string) ([]byte, error) {
	if m.Capability != "private" {
		return nil, fmt.Errorf("no private key")
	}
	data := []byte("VaultysID/" + message + "/end")
	return crypto.HMAC("sha256", m.Cypher.SecretKey, data), nil
}

func (m *DilithiumManager) GetVersion() int {
	return m.Version
}

func (m *DilithiumManager) SetVersion(version int) error {
	if version != 0 && version != 1 {
		return fmt.Errorf("unsupported version: %d", version)
	}
	m.Version = version
	return nil
}

func (m *DilithiumManager) CleanSecureData() {
	if m.Cypher.SecretKey != nil {
		crypto.SecureErase(m.Cypher.SecretKey)
		m.Cypher.SecretKey = nil
	}
	if m.Signer.SecretKey != nil {
		crypto.SecureErase(m.Signer.SecretKey)
		m.Signer.SecretKey = nil
	}
	if m.Seed != nil {
		crypto.SecureErase(m.Seed)
		m.Seed = nil
	}
	if m.Entropy != nil {
		crypto.SecureErase(m.Entropy)
		m.Entropy = nil
	}
}
