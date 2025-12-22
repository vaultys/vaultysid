package keymanager

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

// Exported functions for Ed25519Manager
var (
	CreateFromEntropy = CreateEd25519FromEntropy
	Generate          = GenerateEd25519
	FromSecret        = Ed25519FromSecret
	FromID            = Ed25519FromID
)

// CreateEd25519FromEntropy creates an Ed25519Manager from entropy
func CreateEd25519FromEntropy(entropy []byte) (KeyManager, error) {
	return createEd25519FromEntropy(entropy)
}

// GenerateEd25519 generates a new Ed25519Manager with random entropy
func GenerateEd25519() (KeyManager, error) {
	return generateEd25519()
}

// Ed25519FromSecret creates an Ed25519Manager from a secret
func Ed25519FromSecret(secret []byte) (KeyManager, error) {
	return fromSecretEd25519(secret)
}

// Ed25519FromID creates an Ed25519Manager from an ID (public only)
func Ed25519FromID(id []byte) (KeyManager, error) {
	return fromIDEd25519(id)
}

// Helper functions that the Ed25519Manager will implement
func createEd25519FromEntropy(entropy []byte) (*Ed25519Manager, error) {
	return CreateFromEntropyInternal(entropy)
}

func generateEd25519() (*Ed25519Manager, error) {
	return GenerateInternal()
}

func fromSecretEd25519(secret []byte) (*Ed25519Manager, error) {
	return FromSecretInternal(secret)
}

func fromIDEd25519(id []byte) (*Ed25519Manager, error) {
	return FromIDInternal(id)
}
