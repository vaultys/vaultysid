//go:build ignore
// +build ignore

// Run this file with: go run generate_rfc_dhies_vector.go
// It regenerates rfc/vectors/dhies.json.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/vaultys/vaultysid/go/pkg/crypto"
	"github.com/vaultys/vaultysid/go/pkg/keymanager"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
	"golang.org/x/crypto/curve25519"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func fixedBytes(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func main() {
	aliceEntropy := fixedBytes(0x40, 32)
	bobEntropy := fixedBytes(0x60, 32)

	alice, err := vaultysid.FromEntropy(aliceEntropy, vaultysid.TypePerson)
	must(err)
	bob, err := vaultysid.FromEntropy(bobEntropy, vaultysid.TypePerson)
	must(err)

	aliceKM := alice.KeyManager.(*keymanager.Ed25519Manager)
	bobKM := bob.KeyManager.(*keymanager.Ed25519Manager)

	dhiesAlice, err := keymanager.NewDHIES(aliceKM)
	must(err)
	dhiesBob, err := keymanager.NewDHIES(bobKM)
	must(err)

	plaintext := []byte("Vaultys DHIES reference vector: this message is encrypted by Alice for Bob.")

	// Fixed ephemeral scalar + fixed nonce so the whole vector is reproducible.
	ephemeralPrivate := fixedBytes(0x01, 32)
	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	must(err)
	nonce := fixedBytes(0x02, 24)

	// Manually replicate DHIES.Encrypt with the fixed ephemeral key/nonce
	// (production Encrypt() always generates these randomly). We then
	// validate the result with the REAL, unmodified Decrypt() -- if that
	// succeeds, this manual construction is provably byte-compatible with
	// the actual implementation, not just a hand-rolled approximation.
	shared, err := curve25519.X25519(ephemeralPrivate, bobKM.Cypher.PublicKey)
	must(err)

	// dhiesKDF/dhiesMAC are unexported; reproduce them inline here using
	// only public primitives, matching pkg/keymanager/dhies.go exactly.
	context := append([]byte("DHIES-KDF"), append(append([]byte{}, aliceKM.Cypher.PublicKey...), bobKM.Cypher.PublicKey...)...)
	encMaterial := crypto.Hash("sha512", append(append(append([]byte{}, shared...), context...), 0x01))
	macMaterial := crypto.Hash("sha512", append(append(append([]byte{}, shared...), context...), 0x02))
	encKey := encMaterial[:32]
	macKey := macMaterial[:32]

	ciphertext, err := crypto.Encrypt(plaintext, encKey, nonce)
	must(err)

	toAuth := append(append(append([]byte{}, aliceKM.Cypher.PublicKey...), nonce...), ciphertext...)
	mac := crypto.Hash("sha256", append(append([]byte{}, macKey...), toAuth...))

	message := append(append(append(append([]byte{}, nonce...), ephemeralPublic...), ciphertext...), mac...)

	// Validate with the real, unmodified Decrypt().
	decrypted, err := dhiesBob.Decrypt(message, aliceKM.Cypher.PublicKey)
	must(err)
	if string(decrypted) != string(plaintext) {
		panic("decrypted plaintext does not match original")
	}

	// Also validate a real (non-deterministic) round trip through the
	// production Encrypt/Decrypt path, to prove the fixed-ephemeral
	// reconstruction above isn't the only path that works.
	prodCiphertext, err := dhiesAlice.Encrypt(bobKM.Cypher.PublicKey, plaintext)
	must(err)
	prodDecrypted, err := dhiesBob.Decrypt(prodCiphertext, aliceKM.Cypher.PublicKey)
	must(err)
	if string(prodDecrypted) != string(plaintext) {
		panic("production round trip mismatch")
	}

	// Tamper check: flipping one ciphertext byte must be rejected.
	tampered := append([]byte{}, message...)
	tampered[70] ^= 0xFF
	_, tamperErr := dhiesBob.Decrypt(tampered, aliceKM.Cypher.PublicKey)

	out := map[string]interface{}{
		"description": "Deterministic DHIES (Diffie-Hellman Integrated Encryption Scheme) reference vector, fixing the normally-random ephemeral key and nonce so the ciphertext is reproducible. Validated with the real, unmodified DHIES.Decrypt(); a tamper check and an independent production (random ephemeral) round trip are included for completeness.",
		"wireFormat":  "nonce(24) || ephemeralPublicKey(32) || secretbox_ciphertext(len(plaintext)+16) || mac(32)",
		"kdf":         "encKey = SHA-512(sharedSecret || \"DHIES-KDF\" || senderStaticPub || recipientStaticPub || 0x01)[0:32]; macKey = same with 0x02 instead of 0x01",
		"mac":         "SHA-256(macKey || senderStaticPublicKey || nonce || ciphertext)",
		"identities": map[string]interface{}{
			"alice": map[string]string{"entropyHex": hex.EncodeToString(aliceEntropy), "cypherPublicKeyHex": hex.EncodeToString(aliceKM.Cypher.PublicKey)},
			"bob":   map[string]string{"entropyHex": hex.EncodeToString(bobEntropy), "cypherPublicKeyHex": hex.EncodeToString(bobKM.Cypher.PublicKey)},
		},
		"inputs": map[string]string{
			"plaintextUtf8":      string(plaintext),
			"ephemeralPrivateHex": hex.EncodeToString(ephemeralPrivate),
			"ephemeralPublicHex": hex.EncodeToString(ephemeralPublic),
			"nonceHex":           hex.EncodeToString(nonce),
		},
		"derived": map[string]string{
			"sharedSecretHex": hex.EncodeToString(shared),
			"encKeyHex":       hex.EncodeToString(encKey),
			"macKeyHex":       hex.EncodeToString(macKey),
			"macHex":          hex.EncodeToString(mac),
		},
		"output": map[string]interface{}{
			"messageHex":              hex.EncodeToString(message),
			"messageLength":           len(message),
			"decryptedByRealDecrypt":  string(decrypted) == string(plaintext),
			"tamperedMessageRejected": tamperErr != nil,
			"tamperErrorMessage":      fmt.Sprintf("%v", tamperErr),
		},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(out))
}
