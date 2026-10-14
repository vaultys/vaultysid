package keymanager

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
)

// DHIES v2: sender-authenticated Diffie-Hellman Integrated Encryption Scheme.
//
// Shared cross-language spec (TypeScript is the reference):
//
//	(e_sk, e_pk) = fresh X25519 keypair
//	es   = X25519(e_sk, R_pk)
//	ss   = X25519(S_sk, R_pk)          (either all zero -> reject)
//	info = "VAULTYS_DHIES_V2" || e_pk || S_pk || R_pk
//	k    = SHA-512(es || ss || info)[0:32]
//	ct   = XSalsa20-Poly1305 secretbox(plaintext, nonce(24 random), k)
//	out  = 0x02 || nonce || e_pk || ct
//
// Decryption recomputes es = X25519(R_sk, e_pk) and ss = X25519(R_sk, S_pk);
// a ciphertext only opens under the (sender, recipient) pair it was made
// for, so a forged sender public key is rejected by the Poly1305 tag.
const (
	DHIESV2Version  = 0x02
	dhiesNonceSize  = 24
	dhiesKeySize    = 32
	dhiesHeaderSize = 1 + dhiesNonceSize + dhiesKeySize
	// DHIESV2MinSize is the size of a DHIES v2 ciphertext of an empty plaintext.
	DHIESV2MinSize = dhiesHeaderSize + secretbox.Overhead
)

var dhiesV2Info = []byte("VAULTYS_DHIES_V2")

// ErrDHIESDecrypt is returned for any DHIES v2 decryption failure; the
// cause is deliberately not distinguished.
var ErrDHIESDecrypt = errors.New("DHIES: decryption failed")

// cypherKeyHolder is what DHIES needs from a key manager.
type cypherKeyHolder interface {
	CypherSecretProvider
	GetCypherPublicKey() []byte
}

// DHIES binds DHIES v2 operations to one static X25519 keypair.
type DHIES struct {
	privateKey []byte
	publicKey  []byte
}

// NewDHIES creates a DHIES instance from any private key manager holding an
// X25519 keypair (Ed25519, Dilithium, FIDO2 software secret).
func NewDHIES(km cypherKeyHolder) (*DHIES, error) {
	sk, err := km.GetCypherSecretKey()
	if err != nil {
		return nil, fmt.Errorf("DHIES requires private key: %w", err)
	}
	pk := km.GetCypherPublicKey()
	if len(sk) != dhiesKeySize || len(pk) != dhiesKeySize {
		return nil, fmt.Errorf("DHIES requires 32-byte X25519 keys")
	}
	return &DHIES{privateKey: sk, publicKey: pk}, nil
}

// NewDHIESFromKeys creates a DHIES instance from a raw X25519 keypair.
func NewDHIESFromKeys(secretKey, publicKey []byte) (*DHIES, error) {
	if len(secretKey) != dhiesKeySize || len(publicKey) != dhiesKeySize {
		return nil, fmt.Errorf("DHIES requires 32-byte X25519 keys")
	}
	return &DHIES{privateKey: secretKey, publicKey: publicKey}, nil
}

// Encrypt encrypts plaintext from this (sender) keypair to recipientPublicKey.
func (d *DHIES) Encrypt(recipientPublicKey []byte, plaintext []byte) ([]byte, error) {
	return DHIESEncryptV2(d.privateKey, d.publicKey, recipientPublicKey, plaintext)
}

// Decrypt opens a message addressed to this (recipient) keypair and
// authenticated by senderPublicKey.
func (d *DHIES) Decrypt(message []byte, senderPublicKey []byte) ([]byte, error) {
	return DHIESDecryptV2(d.privateKey, d.publicKey, senderPublicKey, message)
}

// x25519 computes a non-zero shared secret or fails.
func x25519(scalar, point []byte) ([]byte, error) {
	if len(scalar) != dhiesKeySize || len(point) != dhiesKeySize {
		return nil, fmt.Errorf("X25519 keys must be 32 bytes")
	}
	// curve25519.X25519 already rejects an all-zero output (low-order
	// point); the explicit check keeps that guarantee independent of the
	// library version.
	out, err := curve25519.X25519(scalar, point)
	if err != nil {
		return nil, err
	}
	var zero [32]byte
	if subtle.ConstantTimeCompare(out, zero[:]) == 1 {
		return nil, fmt.Errorf("X25519 produced an all-zero shared secret")
	}
	return out, nil
}

// dhiesV2Key derives k = SHA-512(es || ss || info)[0:32] into a fixed array.
func dhiesV2Key(es, ss, ePub, senderPub, recipientPub []byte) *[32]byte {
	h := sha512.New()
	h.Write(es)
	h.Write(ss)
	h.Write(dhiesV2Info)
	h.Write(ePub)
	h.Write(senderPub)
	h.Write(recipientPub)
	sum := h.Sum(nil)
	var k [32]byte
	copy(k[:], sum[:32])
	crypto.SecureErase(sum)
	return &k
}

// DHIESEncryptV2 implements DHIES v2 encryption with explicit keys.
func DHIESEncryptV2(senderSecret, senderPublic, recipientPublic, plaintext []byte) ([]byte, error) {
	if len(senderSecret) != dhiesKeySize || len(senderPublic) != dhiesKeySize || len(recipientPublic) != dhiesKeySize {
		return nil, fmt.Errorf("DHIES: X25519 keys must be 32 bytes")
	}

	ePriv := make([]byte, dhiesKeySize)
	if _, err := io.ReadFull(rand.Reader, ePriv); err != nil {
		return nil, err
	}
	defer crypto.SecureErase(ePriv)

	var nonce [dhiesNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	return dhiesEncryptV2Deterministic(ePriv, &nonce, senderSecret, senderPublic, recipientPublic, plaintext)
}

// dhiesEncryptV2Deterministic is DHIESEncryptV2 with caller-supplied
// ephemeral secret and nonce. Only for known-answer tests: reusing an
// ephemeral key or nonce breaks confidentiality.
func dhiesEncryptV2Deterministic(ePriv []byte, nonce *[dhiesNonceSize]byte, senderSecret, senderPublic, recipientPublic, plaintext []byte) ([]byte, error) {
	ePub, err := curve25519.X25519(ePriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	es, err := x25519(ePriv, recipientPublic)
	if err != nil {
		return nil, fmt.Errorf("DHIES: %w", err)
	}
	defer crypto.SecureErase(es)

	ss, err := x25519(senderSecret, recipientPublic)
	if err != nil {
		return nil, fmt.Errorf("DHIES: %w", err)
	}
	defer crypto.SecureErase(ss)

	k := dhiesV2Key(es, ss, ePub, senderPublic, recipientPublic)
	defer crypto.SecureErase(k[:])

	out := make([]byte, 0, dhiesHeaderSize+len(plaintext)+secretbox.Overhead)
	out = append(out, DHIESV2Version)
	out = append(out, nonce[:]...)
	out = append(out, ePub...)
	out = secretbox.Seal(out, plaintext, nonce, k)
	return out, nil
}

// DHIESDecryptV2 implements DHIES v2 decryption with explicit keys.
func DHIESDecryptV2(recipientSecret, recipientPublic, senderPublic, message []byte) ([]byte, error) {
	if len(recipientSecret) != dhiesKeySize || len(recipientPublic) != dhiesKeySize || len(senderPublic) != dhiesKeySize {
		return nil, ErrDHIESDecrypt
	}
	if len(message) < DHIESV2MinSize || message[0] != DHIESV2Version {
		return nil, ErrDHIESDecrypt
	}

	var nonce [dhiesNonceSize]byte
	copy(nonce[:], message[1:1+dhiesNonceSize])
	ePub := message[1+dhiesNonceSize : dhiesHeaderSize]
	ct := message[dhiesHeaderSize:]

	es, err := x25519(recipientSecret, ePub)
	if err != nil {
		return nil, ErrDHIESDecrypt
	}
	defer crypto.SecureErase(es)

	ss, err := x25519(recipientSecret, senderPublic)
	if err != nil {
		return nil, ErrDHIESDecrypt
	}
	defer crypto.SecureErase(ss)

	k := dhiesV2Key(es, ss, ePub, senderPublic, recipientPublic)
	defer crypto.SecureErase(k[:])

	plaintext, ok := secretbox.Open(nil, ct, &nonce, k)
	if !ok {
		return nil, ErrDHIESDecrypt
	}
	return plaintext, nil
}
