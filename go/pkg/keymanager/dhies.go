package keymanager

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/vaultys/vaultysid-go/pkg/crypto"
	"golang.org/x/crypto/curve25519"
)

// DHIES implements Diffie-Hellman Integrated Encryption Scheme.
//
// Wire format and key derivation match the TypeScript reference
// (KeyManager/CypherManager.ts) so ciphertexts produced by one
// implementation can be decrypted by the other:
//
//	nonce(24) || ephemeralPublicKey(32) || secretbox(plaintext) || mac(32)
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

// dhiesKDF derives an encryption key and a MAC key from a shared secret,
// matching TS CypherManager.DHIES.kdf: SHA-512(shared || "DHIES-KDF" || pubA || pubB || domainByte).
func dhiesKDF(shared, pubA, pubB []byte) (encKey, macKey []byte) {
	context := make([]byte, 0, len("DHIES-KDF")+len(pubA)+len(pubB))
	context = append(context, []byte("DHIES-KDF")...)
	context = append(context, pubA...)
	context = append(context, pubB...)

	encMaterial := crypto.Hash("sha512", append(append(append([]byte{}, shared...), context...), 0x01))
	macMaterial := crypto.Hash("sha512", append(append(append([]byte{}, shared...), context...), 0x02))

	return encMaterial[:32], macMaterial[:32]
}

// dhiesMAC computes the outer authentication tag, matching TS computeMAC: SHA-256(macKey || data).
func dhiesMAC(macKey, data []byte) []byte {
	return crypto.Hash("sha256", append(append([]byte{}, macKey...), data...))
}

// Encrypt encrypts data for a recipient's public key
func (d *DHIES) Encrypt(recipientPublicKey []byte, plaintext []byte) ([]byte, error) {
	ephemeralPrivate := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivate); err != nil {
		return nil, err
	}
	defer crypto.SecureErase(ephemeralPrivate)

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	shared, err := curve25519.X25519(ephemeralPrivate, recipientPublicKey)
	if err != nil {
		return nil, err
	}
	defer crypto.SecureErase(shared)

	encKey, macKey := dhiesKDF(shared, d.publicKey, recipientPublicKey)
	defer crypto.SecureErase(encKey)
	defer crypto.SecureErase(macKey)

	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext, err := crypto.Encrypt(plaintext, encKey, nonce)
	if err != nil {
		return nil, err
	}

	toAuthenticate := make([]byte, 0, len(d.publicKey)+len(nonce)+len(ciphertext))
	toAuthenticate = append(toAuthenticate, d.publicKey...)
	toAuthenticate = append(toAuthenticate, nonce...)
	toAuthenticate = append(toAuthenticate, ciphertext...)
	mac := dhiesMAC(macKey, toAuthenticate)

	result := make([]byte, 0, len(nonce)+len(ephemeralPublic)+len(ciphertext)+len(mac))
	result = append(result, nonce...)
	result = append(result, ephemeralPublic...)
	result = append(result, ciphertext...)
	result = append(result, mac...)

	return result, nil
}

// Decrypt decrypts a message produced by Encrypt, verifying it came from senderPublicKey.
func (d *DHIES) Decrypt(message []byte, senderPublicKey []byte) ([]byte, error) {
	const minLen = 24 + 32 + 32 // nonce + ephemeralPublic + mac (ciphertext may be empty plaintext + 16-byte overhead, but check that separately)
	if len(message) < minLen {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := message[:24]
	ephemeralPublic := message[24:56]
	mac := message[len(message)-32:]
	ciphertext := message[56 : len(message)-32]

	shared, err := curve25519.X25519(d.privateKey, ephemeralPublic)
	if err != nil {
		return nil, err
	}
	defer crypto.SecureErase(shared)

	encKey, macKey := dhiesKDF(shared, senderPublicKey, d.publicKey)
	defer crypto.SecureErase(encKey)
	defer crypto.SecureErase(macKey)

	toAuthenticate := make([]byte, 0, len(senderPublicKey)+len(nonce)+len(ciphertext))
	toAuthenticate = append(toAuthenticate, senderPublicKey...)
	toAuthenticate = append(toAuthenticate, nonce...)
	toAuthenticate = append(toAuthenticate, ciphertext...)
	expectedMAC := dhiesMAC(macKey, toAuthenticate)

	if subtle.ConstantTimeCompare(mac, expectedMAC) != 1 {
		return nil, fmt.Errorf("DHIES: MAC verification failed")
	}

	plaintext, err := crypto.Decrypt(ciphertext, encKey, nonce)
	if err != nil {
		return nil, fmt.Errorf("DHIES: decryption failed: %w", err)
	}

	return plaintext, nil
}
