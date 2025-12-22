package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"

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
