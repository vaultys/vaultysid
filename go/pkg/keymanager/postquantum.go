package keymanager

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"github.com/vmihailenco/msgpack/v5"
)

// Post-quantum identities (rfc/PQ-ENCRYPTION.md §3, §4): a Dilithium or Hybrid
// key manager whose 64-byte seed also derives an ML-KEM-768 key pair, published
// in the id as field `k`, and a PRF key that replaces the X25519 secret in
// HMAC and getSecretHash.

const (
	// MLKEM768PublicKeySize is the size of the encapsulation key `k`.
	MLKEM768PublicKeySize = mlkem768.PublicKeySize // 1184
	// MLKEM768CiphertextSize is the size of an ML-KEM-768 ciphertext.
	MLKEM768CiphertextSize = mlkem768.CiphertextSize // 1088
	// pqSeedSize is the size of the key-manager seed.
	pqSeedSize = 64
)

var (
	mlkemKeygenLabel = []byte("VAULTYS_MLKEM768_KEYGEN")
	prfKeyLabel      = []byte("VAULTYS_PRF_KEY")
)

// PostQuantumKeyManager is implemented by the key managers that can back a
// post-quantum identity (Dilithium and Hybrid).
type PostQuantumKeyManager interface {
	KeyManager
	// EnablePostQuantum derives the ML-KEM-768 key pair and the PRF key from
	// the seed. It requires the secret.
	EnablePostQuantum() error
	// IsPostQuantum reports whether the key manager carries an ML-KEM key.
	IsPostQuantum() bool
	// GetKEMPublicKey returns the ML-KEM-768 encapsulation key, or nil.
	GetKEMPublicKey() []byte
	// KEMDecapsulate decapsulates an ML-KEM-768 ciphertext with the
	// decapsulation key re-derived from the seed.
	KEMDecapsulate(ciphertext []byte) ([]byte, error)
	// GetSecretHash is SHA-256(data || "secrethash" || key), the key being
	// the PRF key of a post-quantum identity and the X25519 secret otherwise.
	GetSecretHash(data []byte) ([]byte, error)
}

// mlkemSeed returns dz = SHA-512("VAULTYS_MLKEM768_KEYGEN" || seed).
func mlkemSeed(seed []byte) []byte {
	h := sha512.New()
	h.Write(mlkemKeygenLabel)
	h.Write(seed)
	return h.Sum(nil)
}

// DeriveMLKEMPublicKey returns the ML-KEM-768 encapsulation key of a 64-byte
// seed: KeyGen_internal(d, z) with d || z = SHA-512(label || seed) (§3.1).
func DeriveMLKEMPublicKey(seed []byte) ([]byte, error) {
	pk, _, err := deriveMLKEM(seed)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func deriveMLKEM(seed []byte) ([]byte, *mlkem768.PrivateKey, error) {
	if len(seed) != pqSeedSize {
		return nil, nil, fmt.Errorf("post-quantum seed must be %d bytes, got %d", pqSeedSize, len(seed))
	}
	dz := mlkemSeed(seed)
	defer crypto.SecureErase(dz)
	pk, sk := mlkem768.NewKeyFromSeed(dz)
	ek := make([]byte, MLKEM768PublicKeySize)
	pk.Pack(ek)
	return ek, sk, nil
}

// DerivePRFKey returns SHA-512("VAULTYS_PRF_KEY" || seed)[0:32] (§3.2).
func DerivePRFKey(seed []byte) ([]byte, error) {
	if len(seed) != pqSeedSize {
		return nil, fmt.Errorf("post-quantum seed must be %d bytes, got %d", pqSeedSize, len(seed))
	}
	h := sha512.New()
	h.Write(prfKeyLabel)
	h.Write(seed)
	sum := h.Sum(nil)
	key := make([]byte, 32)
	copy(key, sum[:32])
	crypto.SecureErase(sum)
	return key, nil
}

// pqKeys holds the post-quantum part of a Dilithium or Hybrid key manager.
// The decapsulation key is never stored: it is re-derived from the seed.
type pqKeys struct {
	// KEMPublicKey is the ML-KEM-768 encapsulation key (field `k`), nil for a
	// classical identity.
	KEMPublicKey []byte
	// prfKey is the seed-derived PRF key, nil for a classical identity or a
	// public-only key manager.
	prfKey []byte
}

func (p *pqKeys) enable(seed []byte) error {
	ek, _, err := deriveMLKEM(seed)
	if err != nil {
		return err
	}
	prf, err := DerivePRFKey(seed)
	if err != nil {
		return err
	}
	p.KEMPublicKey = ek
	p.prfKey = prf
	return nil
}

func (p *pqKeys) isPostQuantum() bool {
	return len(p.KEMPublicKey) == MLKEM768PublicKeySize
}

func (p *pqKeys) decapsulate(seed, ciphertext []byte) ([]byte, error) {
	if !p.isPostQuantum() || len(seed) != pqSeedSize {
		return nil, fmt.Errorf("no ML-KEM decapsulation key")
	}
	if len(ciphertext) != MLKEM768CiphertextSize {
		return nil, fmt.Errorf("ML-KEM-768 ciphertext must be %d bytes", MLKEM768CiphertextSize)
	}
	_, sk, err := deriveMLKEM(seed)
	if err != nil {
		return nil, err
	}
	ss := make([]byte, mlkem768.SharedKeySize)
	sk.DecapsulateTo(ss, ciphertext)
	return ss, nil
}

// hmacKey is the key behind HMAC and GetSecretHash: the PRF key for a
// post-quantum identity, the X25519 secret otherwise.
// A post-quantum identity never falls back to the X25519 secret.
func (p *pqKeys) hmacKey(cypherSecret []byte) ([]byte, error) {
	if p.isPostQuantum() {
		if len(p.prfKey) != 32 {
			return nil, fmt.Errorf("no PRF key available")
		}
		return p.prfKey, nil
	}
	if len(cypherSecret) != 32 {
		return nil, fmt.Errorf("no private encryption key available")
	}
	return cypherSecret, nil
}

func (p *pqKeys) clean() {
	if p.prfKey != nil {
		crypto.SecureErase(p.prfKey)
		p.prfKey = nil
	}
}

func secretHash(data, key []byte) []byte {
	h := sha256.New()
	h.Write(data)
	h.Write([]byte("secrethash"))
	h.Write(key)
	return h.Sum(nil)
}

// pqDataExport is the key-manager record of an id: {v, x, e} for a classical
// identity, {v, x, e, k} for a post-quantum one (§4.3), in this order.
type pqDataExport struct {
	V int    `msgpack:"v"`
	X []byte `msgpack:"x"`
	E []byte `msgpack:"e"`
	K []byte `msgpack:"k,omitempty"`
}

func encodeKeyManagerRecord(version int, x, e, k []byte) []byte {
	encoded, _ := msgpack.Marshal(pqDataExport{V: version, X: x, E: e, K: k})
	return encoded
}

// PostQuantumFromID parses the key-manager record of a post-quantum id
// (everything after the type byte), following rfc/PQ-ENCRYPTION.md §4.2:
// version 1, a 32-byte e, a 1184-byte k, and a key manager selected by the
// length of x (2592 bytes: Dilithium, 2624 bytes: Hybrid). Anything else,
// in particular an Ed25519 key manager, is rejected.
func PostQuantumFromID(id []byte) (PostQuantumKeyManager, error) {
	var data pqDataExport
	if err := msgpack.Unmarshal(id, &data); err != nil {
		return nil, fmt.Errorf("invalid post-quantum id: %w", err)
	}
	if data.V != 1 {
		return nil, fmt.Errorf("invalid post-quantum id: version must be 1, got %d", data.V)
	}
	if data.K == nil {
		return nil, fmt.Errorf("invalid post-quantum id: missing ML-KEM key")
	}
	if len(data.K) != MLKEM768PublicKeySize {
		return nil, fmt.Errorf("invalid post-quantum id: ML-KEM key must be %d bytes, got %d", MLKEM768PublicKeySize, len(data.K))
	}
	if len(data.E) != x25519KeySize {
		return nil, fmt.Errorf("invalid post-quantum id: encryption key must be 32 bytes, got %d", len(data.E))
	}
	switch len(data.X) {
	case mldsa87.PublicKeySize:
		km := &DilithiumManager{Version: 1, Capability: "public"}
		km.Signer = KeyPair{PublicKey: data.X}
		km.Cypher = KeyPair{PublicKey: data.E}
		km.KEMPublicKey = data.K
		return km, nil
	case HybridPublicKeySize:
		km, err := hybridFromKeys(1, data.X, data.E)
		if err != nil {
			return nil, err
		}
		km.KEMPublicKey = data.K
		return km, nil
	default:
		return nil, fmt.Errorf("invalid post-quantum id: unsupported key manager (signing key of %d bytes)", len(data.X))
	}
}

// PostQuantumFromSecret restores the key manager of a post-quantum identity
// from its secret record (everything after the type byte). As in TypeScript,
// the record length selects the key manager (72 bytes: Dilithium, 83 bytes:
// Hybrid); the version must be 1.
func PostQuantumFromSecret(secret []byte) (PostQuantumKeyManager, error) {
	switch len(secret) {
	case 72:
		km, err := FromSecretDilithiumInternal(secret)
		if err != nil {
			return nil, err
		}
		if km.Version != 1 {
			km.CleanSecureData()
			return nil, fmt.Errorf("post-quantum secrets must be serialized with version 1")
		}
		if err := km.EnablePostQuantum(); err != nil {
			km.CleanSecureData()
			return nil, err
		}
		return km, nil
	case 83:
		km, err := HybridFromSecret(secret)
		if err != nil {
			return nil, err
		}
		if km.Version != 1 {
			km.CleanSecureData()
			return nil, fmt.Errorf("post-quantum secrets must be serialized with version 1")
		}
		if err := km.EnablePostQuantum(); err != nil {
			km.CleanSecureData()
			return nil, err
		}
		return km, nil
	default:
		return nil, fmt.Errorf("post-quantum secret with an unsupported key manager")
	}
}
