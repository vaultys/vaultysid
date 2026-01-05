package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"

	"time"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

// RandomBytes generates cryptographically secure random bytes
func RandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("invalid length: %d", length)
	}
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

// Hash computes SHA256 hash by default, supports sha224, sha256, sha512
func Hash(algorithm string, data []byte) []byte {
	switch algorithm {
	case "sha224":
		sum := sha256.Sum224(data)
		return sum[:]
	case "sha512":
		sum := sha512.Sum512(data)
		return sum[:]
	case "sha256", "":
		sum := sha256.Sum256(data)
		return sum[:]
	case "sha3-256":
		sum := sha3.Sum256(data)
		return sum[:]
	default:
		// Default to SHA256 for unknown algorithms (matching TypeScript behavior)
		sum := sha256.Sum256(data)
		return sum[:]
	}
}

// HMAC computes an HMAC using the specified hash algorithm
func HMAC(algorithm string, key []byte, data []byte) []byte {
	var h hash.Hash
	switch algorithm {
	case "sha512":
		h = hmac.New(sha512.New, key)
	case "sha256", "":
		h = hmac.New(sha256.New, key)
	default:
		h = hmac.New(sha256.New, key)
	}
	h.Write(data)
	return h.Sum(nil)
}

// SecureErase zeroes out the contents of a byte slice
func SecureErase(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Now returns the current Unix timestamp in milliseconds
func Now() int64 {
	return time.Now().UnixNano() / 1000000
}

// PasswordEncrypt encrypts data with a password using scrypt and nacl secretbox
func PasswordEncrypt(data []byte, password string) ([]byte, error) {
	// Generate a random salt
	salt, err := RandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key from password using scrypt
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Generate a random nonce
	nonce, err := RandomBytes(24)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Convert key to [32]byte
	var secretKey [32]byte
	copy(secretKey[:], key)

	// Convert nonce to [24]byte
	var nonceArray [24]byte
	copy(nonceArray[:], nonce)

	// Encrypt the data
	encrypted := secretbox.Seal(nil, data, &nonceArray, &secretKey)

	// Combine salt + nonce + encrypted data
	result := make([]byte, 0, 32+24+len(encrypted))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, encrypted...)

	return result, nil
}

// PasswordDecrypt decrypts data encrypted with PasswordEncrypt
func PasswordDecrypt(encrypted []byte, password string) ([]byte, error) {
	if len(encrypted) < 56 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract salt, nonce, and ciphertext
	salt := encrypted[:32]
	nonce := encrypted[32:56]
	ciphertext := encrypted[56:]

	// Derive key from password using scrypt
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Convert key to [32]byte
	var secretKey [32]byte
	copy(secretKey[:], key)

	// Convert nonce to [24]byte
	var nonceArray [24]byte
	copy(nonceArray[:], nonce)

	// Decrypt the data
	decrypted, ok := secretbox.Open(nil, ciphertext, &nonceArray, &secretKey)
	if !ok {
		return nil, fmt.Errorf("failed to decrypt data")
	}

	return decrypted, nil
}

// Encrypt encrypts data using nacl secretbox
func Encrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}
	if len(nonce) != 24 {
		return nil, fmt.Errorf("nonce must be 24 bytes")
	}

	// Convert key to [32]byte
	var secretKey [32]byte
	copy(secretKey[:], key)

	// Convert nonce to [24]byte
	var nonceArray [24]byte
	copy(nonceArray[:], nonce)

	// Encrypt the data
	encrypted := secretbox.Seal(nil, data, &nonceArray, &secretKey)
	return encrypted, nil
}

// Decrypt decrypts data using nacl secretbox
func Decrypt(encrypted []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}
	if len(nonce) != 24 {
		return nil, fmt.Errorf("nonce must be 24 bytes")
	}

	// Convert key to [32]byte
	var secretKey [32]byte
	copy(secretKey[:], key)

	// Convert nonce to [24]byte
	var nonceArray [24]byte
	copy(nonceArray[:], nonce)

	// Decrypt the data
	decrypted, ok := secretbox.Open(nil, encrypted, &nonceArray, &secretKey)
	if !ok {
		return nil, fmt.Errorf("failed to decrypt data")
	}

	return decrypted, nil
}
