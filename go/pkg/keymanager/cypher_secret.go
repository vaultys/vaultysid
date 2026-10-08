package keymanager

import "fmt"

// CypherSecretProvider is implemented by the key managers that hold an X25519
// (encryption) key pair. It is what saltpack encryption needs from an identity:
// the raw secret key to open — or authenticate — a message.
//
// Kept out of the KeyManager interface on purpose: only the decrypting side
// needs it, and a public-only manager has nothing to return.
type CypherSecretProvider interface {
	GetCypherSecretKey() ([]byte, error)
}

func cypherSecret(capability string, pair KeyPair) ([]byte, error) {
	if capability != "private" || len(pair.SecretKey) != 32 {
		return nil, fmt.Errorf("no private encryption key available")
	}
	return pair.SecretKey, nil
}

// GetCypherSecretKey returns the X25519 secret key.
func (m *Ed25519Manager) GetCypherSecretKey() ([]byte, error) {
	return cypherSecret(m.Capability, m.Cypher)
}

// GetCypherSecretKey returns the X25519 secret key.
func (m *DilithiumManager) GetCypherSecretKey() ([]byte, error) {
	return cypherSecret(m.Capability, m.Cypher)
}

// GetCypherSecretKey returns the X25519 secret key.
func (m *FIDO2Manager) GetCypherSecretKey() ([]byte, error) {
	return cypherSecret(m.Capability, m.Cypher)
}

var (
	_ CypherSecretProvider = (*Ed25519Manager)(nil)
	_ CypherSecretProvider = (*DilithiumManager)(nil)
	_ CypherSecretProvider = (*FIDO2Manager)(nil)
)
