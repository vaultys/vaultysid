package keymanager

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
)

// DHIES v3: DHIES v2 plus an ML-KEM-768 encapsulation to a post-quantum
// recipient (rfc/PQ-ENCRYPTION.md §5). TypeScript is the reference:
//
//	(e_sk, e_pk)  = fresh X25519 key pair
//	es            = X25519(e_sk, R_pk)
//	ss            = X25519(S_sk, R_pk)          (either all zero -> reject)
//	(kem_ct, kss) = ML-KEM-768.Encaps(R_ek)
//	info          = "VAULTYS_DHIES_V3" || e_pk || S_pk || R_pk || SHA-256(R_ek) || kem_ct
//	k             = SHA-512(es || ss || kss || info)[0:32]
//	ct            = XSalsa20-Poly1305 secretbox(plaintext, nonce(24 random), k)
//	out           = 0x03 || nonce || e_pk || kem_ct || ct
//
// Confidential if either X25519 or ML-KEM-768 holds. Sender authentication
// still relies on X25519 (ss).
const (
	DHIESV3Version    = 0x03
	dhiesV3HeaderSize = 1 + dhiesNonceSize + dhiesKeySize + mlkem768.CiphertextSize
	// DHIESV3MinSize is the size of a DHIES v3 message of an empty plaintext
	// (1161 bytes): also its overhead.
	DHIESV3MinSize = dhiesV3HeaderSize + secretbox.Overhead
)

var dhiesV3Info = []byte("VAULTYS_DHIES_V3")

// KEMDecapsulateFunc decapsulates an ML-KEM-768 ciphertext with the
// recipient's decapsulation key.
type KEMDecapsulateFunc func(ciphertext []byte) ([]byte, error)

// dhiesV3Key derives k = SHA-512(es || ss || kss || info)[0:32].
func dhiesV3Key(es, ss, kss, ePub, senderPub, recipientPub, recipientEK, kemCT []byte) *[32]byte {
	ekHash := sha256.Sum256(recipientEK)
	h := sha512.New()
	h.Write(es)
	h.Write(ss)
	h.Write(kss)
	h.Write(dhiesV3Info)
	h.Write(ePub)
	h.Write(senderPub)
	h.Write(recipientPub)
	h.Write(ekHash[:])
	h.Write(kemCT)
	sum := h.Sum(nil)
	var k [32]byte
	copy(k[:], sum[:32])
	crypto.SecureErase(sum)
	return &k
}

// DHIESEncryptV3 encrypts plaintext from the sender's static X25519 key pair
// to a post-quantum recipient (X25519 key and ML-KEM-768 key).
func DHIESEncryptV3(senderSecret, senderPublic, recipientPublic, recipientEK, plaintext []byte) ([]byte, error) {
	ePriv := make([]byte, dhiesKeySize)
	if _, err := io.ReadFull(rand.Reader, ePriv); err != nil {
		return nil, err
	}
	defer crypto.SecureErase(ePriv)

	var nonce [dhiesNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	m := make([]byte, mlkem768.EncapsulationSeedSize)
	if _, err := io.ReadFull(rand.Reader, m); err != nil {
		return nil, err
	}
	defer crypto.SecureErase(m)

	return dhiesEncryptV3Deterministic(ePriv, &nonce, m, senderSecret, senderPublic, recipientPublic, recipientEK, plaintext)
}

// dhiesEncryptV3Deterministic is DHIESEncryptV3 with caller-supplied
// ephemeral secret, nonce and ML-KEM randomness m. Only for known-answer
// tests: reusing any of them breaks confidentiality. Not exported.
func dhiesEncryptV3Deterministic(ePriv []byte, nonce *[dhiesNonceSize]byte, m, senderSecret, senderPublic, recipientPublic, recipientEK, plaintext []byte) ([]byte, error) {
	if len(senderSecret) != dhiesKeySize || len(senderPublic) != dhiesKeySize || len(recipientPublic) != dhiesKeySize {
		return nil, fmt.Errorf("DHIES: X25519 keys must be 32 bytes")
	}
	if len(recipientEK) != MLKEM768PublicKeySize {
		return nil, fmt.Errorf("DHIES: invalid recipient ML-KEM public key")
	}
	if len(m) != mlkem768.EncapsulationSeedSize {
		return nil, fmt.Errorf("DHIES: ML-KEM randomness must be %d bytes", mlkem768.EncapsulationSeedSize)
	}
	// Unpack applies the FIPS 203 encapsulation key check (modulus check).
	var pk mlkem768.PublicKey
	if err := pk.Unpack(recipientEK); err != nil {
		return nil, fmt.Errorf("DHIES: invalid recipient ML-KEM public key")
	}

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

	kemCT := make([]byte, mlkem768.CiphertextSize)
	kss := make([]byte, mlkem768.SharedKeySize)
	pk.EncapsulateTo(kemCT, kss, m)
	defer crypto.SecureErase(kss)

	k := dhiesV3Key(es, ss, kss, ePub, senderPublic, recipientPublic, recipientEK, kemCT)
	defer crypto.SecureErase(k[:])

	out := make([]byte, 0, DHIESV3MinSize+len(plaintext))
	out = append(out, DHIESV3Version)
	out = append(out, nonce[:]...)
	out = append(out, ePub...)
	out = append(out, kemCT...)
	out = secretbox.Seal(out, plaintext, nonce, k)
	return out, nil
}

// DHIESDecryptV3 opens a DHIES v3 message addressed to a post-quantum
// recipient and authenticated by senderPublic. Every failure returns
// ErrDHIESDecrypt, without saying which step failed (§5.3).
func DHIESDecryptV3(recipientSecret, recipientPublic, recipientEK []byte, decapsulate KEMDecapsulateFunc, senderPublic, message []byte) ([]byte, error) {
	if len(recipientSecret) != dhiesKeySize || len(recipientPublic) != dhiesKeySize || len(senderPublic) != dhiesKeySize {
		return nil, ErrDHIESDecrypt
	}
	if len(recipientEK) != MLKEM768PublicKeySize || decapsulate == nil {
		return nil, ErrDHIESDecrypt
	}
	if len(message) < DHIESV3MinSize || message[0] != DHIESV3Version {
		return nil, ErrDHIESDecrypt
	}

	var nonce [dhiesNonceSize]byte
	offset := 1
	copy(nonce[:], message[offset:offset+dhiesNonceSize])
	offset += dhiesNonceSize
	ePub := message[offset : offset+dhiesKeySize]
	offset += dhiesKeySize
	kemCT := message[offset : offset+mlkem768.CiphertextSize]
	ct := message[dhiesV3HeaderSize:]

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
	// ML-KEM implicit rejection: an invalid kem_ct gives a pseudorandom kss
	// and the secretbox check below fails.
	kss, err := decapsulate(kemCT)
	if err != nil || len(kss) != mlkem768.SharedKeySize {
		return nil, ErrDHIESDecrypt
	}
	defer crypto.SecureErase(kss)

	k := dhiesV3Key(es, ss, kss, ePub, senderPublic, recipientPublic, recipientEK, kemCT)
	defer crypto.SecureErase(k[:])

	plaintext, ok := secretbox.Open(nil, ct, &nonce, k)
	if !ok {
		return nil, ErrDHIESDecrypt
	}
	return plaintext, nil
}
