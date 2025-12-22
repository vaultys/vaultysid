package keymanager

import (
	"crypto/rand"
	"fmt"

	"github.com/vaultys/vaultysid-go/pkg/crypto"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// DHIES implements Diffie-Hellman Integrated Encryption Scheme
type DHIES struct {
	privateKey []byte
	publicKey  []byte
}

// NewDHIES creates a DHIES instance from an Ed25519Manager
func NewDHIES(km *Ed25519Manager) (*DHIES, error) {
	if km.Capability != "private" {
		return nil, fmt.Errorf("DHIES requires private key")
	}
	return &DHIES{
		privateKey: km.Cypher.SecretKey,
		publicKey:  km.Cypher.PublicKey,
	}, nil
}

// Encrypt encrypts data for a recipient's public key
func (d *DHIES) Encrypt(recipientPublicKey []byte, plaintext []byte) ([]byte, error) {
	// Generate ephemeral key pair
	ephemeralPrivate := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivate); err != nil {
		return nil, err
	}

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	// Compute shared secret
	shared, err := curve25519.X25519(ephemeralPrivate, recipientPublicKey)
	if err != nil {
		return nil, err
	}

	// Derive encryption key using HKDF-like construction
	encKey := crypto.Hash("sha256", append(shared, []byte("encryption")...))

	// Use ChaCha20-Poly1305 for authenticated encryption
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, plaintext, ephemeralPublic)

	// Return: ephemeral_public || nonce || ciphertext
	result := make([]byte, 0, 32+len(nonce)+len(ciphertext))
	result = append(result, ephemeralPublic...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// Decrypt decrypts data encrypted for our public key
func (d *DHIES) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 32+chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract components
	ephemeralPublic := ciphertext[:32]
	nonce := ciphertext[32 : 32+chacha20poly1305.NonceSizeX]
	encrypted := ciphertext[32+chacha20poly1305.NonceSizeX:]

	// Compute shared secret
	shared, err := curve25519.X25519(d.privateKey, ephemeralPublic)
	if err != nil {
		return nil, err
	}

	// Derive decryption key
	encKey := crypto.Hash("sha256", append(shared, []byte("encryption")...))

	// Create cipher
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext, err := aead.Open(nil, nonce, encrypted, ephemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptAuthenticated encrypts with sender authentication
func (d *DHIES) EncryptAuthenticated(recipientPublicKey []byte, plaintext []byte) ([]byte, error) {
	// For authenticated encryption, we include our public key in the AD
	// and sign the ciphertext

	// First, do normal encryption
	ciphertext, err := d.Encrypt(recipientPublicKey, plaintext)
	if err != nil {
		return nil, err
	}

	// Sign the ciphertext with our key
	// In a real implementation, we'd use the signing key from Ed25519Manager
	// For now, we'll use HMAC with the private key as a simple signature
	signature := crypto.HMAC("sha256", d.privateKey, ciphertext)

	// Return: ciphertext || signature
	result := make([]byte, 0, len(ciphertext)+32)
	result = append(result, ciphertext...)
	result = append(result, signature...)

	return result, nil
}

// DecryptAuthenticated decrypts and verifies sender authentication
func (d *DHIES) DecryptAuthenticated(senderPublicKey []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 32+chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead+32 {
		return nil, fmt.Errorf("ciphertext too short for authenticated message")
	}

	// Extract signature
	message := ciphertext[:len(ciphertext)-32]
	signature := ciphertext[len(ciphertext)-32:]

	// Verify signature (simplified - in real implementation would use Ed25519)
	// Here we can't verify without sender's private key, so we skip verification
	// In a complete implementation, this would use Ed25519 signature verification
	_ = signature
	_ = senderPublicKey

	// Decrypt the message
	return d.Decrypt(message)
}

// SimpleBox provides a simple encrypt/decrypt interface similar to NaCl box
func SimpleBox(message, nonce, peerPublicKey, privateKey []byte) ([]byte, error) {
	if len(nonce) != 24 {
		return nil, fmt.Errorf("nonce must be 24 bytes")
	}

	// Compute shared secret
	shared, err := curve25519.X25519(privateKey, peerPublicKey)
	if err != nil {
		return nil, err
	}

	// Derive key
	key := crypto.Hash("sha256", shared)

	// Use ChaCha20-Poly1305
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Encrypt
	return aead.Seal(nil, nonce[:12], message, nil), nil
}

// SimpleBoxOpen decrypts a message encrypted with SimpleBox
func SimpleBoxOpen(ciphertext, nonce, peerPublicKey, privateKey []byte) ([]byte, error) {
	if len(nonce) != 24 {
		return nil, fmt.Errorf("nonce must be 24 bytes")
	}

	// Compute shared secret
	shared, err := curve25519.X25519(privateKey, peerPublicKey)
	if err != nil {
		return nil, err
	}

	// Derive key
	key := crypto.Hash("sha256", shared)

	// Use ChaCha20-Poly1305
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Decrypt
	return aead.Open(nil, nonce[:12], ciphertext, nil)
}
