package idmanager

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"golang.org/x/crypto/hkdf"
)

// deriveProtocolKey derives a key for a specific protocol (internal use only)
func (m *Manager) deriveProtocolKey(protocol string, version int) (*ProtocolKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get the base secret
	secret, err := m.vaultysID.GetSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	// Create info string for HKDF
	info := fmt.Sprintf("vaultys/protocol/%s/v%d", protocol, version)

	// Derive key using HKDF
	hkdfReader := hkdf.New(sha256.New, secret, nil, []byte(info))
	derivedKey := make([]byte, 32)
	if _, err := hkdfReader.Read(derivedKey); err != nil {
		return nil, fmt.Errorf("failed to derive protocol key: %w", err)
	}

	// Generate public key from derived key (if applicable)
	// This depends on the key manager type
	publicKey := m.derivePublicKey(derivedKey)

	return &ProtocolKey{
		Protocol:  protocol,
		Version:   version,
		PublicKey: publicKey,
		Metadata: map[string]interface{}{
			"derived_at": crypto.Now(),
		},
	}, nil
}

// deriveServiceKey derives a key for a specific service (internal use only)
func (m *Manager) deriveServiceKey(service string, protocol string) (*ServiceKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get the base secret
	secret, err := m.vaultysID.GetSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	// Create salt from service and protocol
	salt := sha256.Sum256([]byte(service + "/" + protocol))

	// Create info string for HKDF
	info := fmt.Sprintf("vaultys/service/%s/%s", service, protocol)

	// Derive key using HKDF
	hkdfReader := hkdf.New(sha256.New, secret, salt[:], []byte(info))
	derivedKey := make([]byte, 32)
	if _, err := hkdfReader.Read(derivedKey); err != nil {
		return nil, fmt.Errorf("failed to derive service key: %w", err)
	}

	// Generate public key from derived key
	publicKey := m.derivePublicKey(derivedKey)

	return &ServiceKey{
		Service:   service,
		Protocol:  protocol,
		PublicKey: publicKey,
		CreatedAt: crypto.Now(),
	}, nil
}

// deriveKey derives a key with custom parameters (internal use only)
func (m *Manager) deriveKey(params *KeyDerivationParams) (*DerivedKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get the base secret
	secret, err := m.vaultysID.GetSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	// Use provided salt or generate one
	salt := params.Salt
	if salt == nil {
		saltHash := sha256.Sum256([]byte(params.Protocol + "/" + params.Service))
		salt = saltHash[:]
	}

	// Use provided info or generate one
	info := params.Info
	if info == nil {
		info = []byte(fmt.Sprintf("vaultys/%s/%s", params.Protocol, params.Service))
	}

	// Determine key length
	keyLength := params.Length
	if keyLength == 0 {
		keyLength = 32 // Default to 256 bits
	}

	// Derive key using HKDF
	hkdfReader := hkdf.New(sha256.New, secret, salt, info)
	derivedKey := make([]byte, keyLength)
	if _, err := hkdfReader.Read(derivedKey); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Generate public key if applicable
	var publicKey []byte
	if keyLength == 32 {
		publicKey = m.derivePublicKey(derivedKey)
	}

	purpose := fmt.Sprintf("%s/%s", params.Protocol, params.Service)

	return &DerivedKey{
		Purpose:   purpose,
		Key:       derivedKey,
		PublicKey: publicKey,
		CreatedAt: crypto.Now(),
	}, nil
}

// deriveHMAC derives an HMAC key for a specific purpose (internal use only)
func (m *Manager) deriveHMAC(purpose string, message []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get the base secret
	secret, err := m.vaultysID.GetSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	// Create HMAC key from purpose
	h := hmac.New(sha256.New, secret)
	h.Write([]byte("vaultys/hmac/" + purpose))
	hmacKey := h.Sum(nil)

	// Generate HMAC of message
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(message)

	return mac.Sum(nil), nil
}

// deriveEncryptionKey derives an encryption key for a specific recipient (internal use only)
func (m *Manager) deriveEncryptionKey(recipientDID string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get the base secret
	secret, err := m.vaultysID.GetSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	// Create salt from DIDs
	myDID := m.vaultysID.DID()
	salt := sha256.Sum256([]byte(myDID + recipientDID))

	// Derive encryption key using HKDF
	info := []byte("vaultys/encryption/" + recipientDID)
	hkdfReader := hkdf.New(sha256.New, secret, salt[:], info)

	encKey := make([]byte, 32)
	if _, err := hkdfReader.Read(encKey); err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	return encKey, nil
}

// deriveSigningKey derives a signing key for a specific context (internal use only)
func (m *Manager) deriveSigningKey(context string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get the base secret
	secret, err := m.vaultysID.GetSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	// Derive signing key using HKDF
	salt := sha256.Sum256([]byte("signing/" + context))
	info := []byte("vaultys/signing/" + context)
	hkdfReader := hkdf.New(sha256.New, secret, salt[:], info)

	signingKey := make([]byte, 32)
	if _, err := hkdfReader.Read(signingKey); err != nil {
		return nil, fmt.Errorf("failed to derive signing key: %w", err)
	}

	return signingKey, nil
}

// deriveSessionKey derives a session key for temporary use (internal use only)
func (m *Manager) deriveSessionKey(sessionID string, ttl int64) (*DerivedKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get the base secret
	secret, err := m.vaultysID.GetSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	// Create salt from session ID
	salt := sha256.Sum256([]byte("session/" + sessionID))

	// Derive session key using HKDF
	info := []byte("vaultys/session/" + sessionID)
	hkdfReader := hkdf.New(sha256.New, secret, salt[:], info)

	sessionKey := make([]byte, 32)
	if _, err := hkdfReader.Read(sessionKey); err != nil {
		return nil, fmt.Errorf("failed to derive session key: %w", err)
	}

	now := crypto.Now()

	return &DerivedKey{
		Purpose:   "session/" + sessionID,
		Key:       sessionKey,
		CreatedAt: now,
		ExpiresAt: now + ttl,
	}, nil
}

// deriveChannelKeys derives symmetric keys for encrypted channel communication (internal use only)
func (m *Manager) deriveChannelKeys(peerPublicKey []byte, nonce []byte) (encKey []byte, macKey []byte, err error) {
	// Perform Diffie-Hellman
	sharedSecret, err := m.vaultysID.DiffieHellman(peerPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to perform DH: %w", err)
	}

	// Combine shared secret with nonce
	combined := append(sharedSecret, nonce...)

	// Derive encryption key
	encInfo := []byte("vaultys/channel/encryption")
	encReader := hkdf.New(sha256.New, combined, nil, encInfo)
	encKey = make([]byte, 32)
	if _, err := encReader.Read(encKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// Derive MAC key
	macInfo := []byte("vaultys/channel/mac")
	macReader := hkdf.New(sha256.New, combined, nil, macInfo)
	macKey = make([]byte, 32)
	if _, err := macReader.Read(macKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive MAC key: %w", err)
	}

	return encKey, macKey, nil
}

// derivePublicKey derives a public key from a private key
// This is a placeholder - actual implementation depends on the key manager type
func (m *Manager) derivePublicKey(privateKey []byte) []byte {
	// For Ed25519, we would derive the public key from the private key
	// For now, return a hash of the private key as a placeholder
	hash := sha256.Sum256(privateKey)
	return hash[:]
}

// getDerivedKeyID returns a deterministic ID for a derived key (internal use only)
func (m *Manager) getDerivedKeyID(purpose string) string {
	did := m.vaultysID.DID()
	combined := did + "/" + purpose
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:16])
}

// storeDerivedKey stores a derived key in the store (internal use only)
func (m *Manager) storeDerivedKey(key *DerivedKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	store := m.store.Substore("derived_keys")
	keyID := m.getDerivedKeyID(key.Purpose)
	store.Set(keyID, key)

	return m.store.Save()
}

// getStoredDerivedKey retrieves a previously derived key (internal use only)
func (m *Manager) getStoredDerivedKey(purpose string) (*DerivedKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	store := m.store.Substore("derived_keys")
	keyID := m.getDerivedKeyID(purpose)

	data := store.Get(keyID)
	if data == nil {
		return nil, fmt.Errorf("derived key not found: %s", purpose)
	}

	if key, ok := data.(*DerivedKey); ok {
		// Check if key has expired
		if key.ExpiresAt > 0 && key.ExpiresAt < crypto.Now() {
			return nil, fmt.Errorf("derived key has expired: %s", purpose)
		}
		return key, nil
	}

	return nil, fmt.Errorf("invalid derived key data")
}

// cleanupExpiredKeys removes expired derived keys from storage (internal use only)
func (m *Manager) cleanupExpiredKeys() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	store := m.store.Substore("derived_keys")
	now := crypto.Now()

	for _, keyID := range store.List() {
		data := store.Get(keyID)
		if key, ok := data.(*DerivedKey); ok {
			if key.ExpiresAt > 0 && key.ExpiresAt < now {
				store.Delete(keyID)
			}
		}
	}

	return m.store.Save()
}
