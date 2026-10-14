//go:build ignore
// +build ignore

// Run this file with: go run generate_rfc_dhies_vector.go
// It regenerates rfc/vectors/dhies.json for DHIES v2 (security spec §3).

package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/vaultys/vaultysid/go/pkg/keymanager"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
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

	plaintext := []byte("Vaultys DHIES v2 reference vector: this message is encrypted by Alice for Bob.")

	// Fixed ephemeral scalar + nonce so the vector is reproducible
	// (production encryption always draws them at random).
	ePriv := fixedBytes(0x01, 32)
	ePub, err := curve25519.X25519(ePriv, curve25519.Basepoint)
	must(err)
	var nonce [24]byte
	copy(nonce[:], fixedBytes(0x02, 24))

	es, err := curve25519.X25519(ePriv, bobKM.Cypher.PublicKey)
	must(err)
	ss, err := curve25519.X25519(aliceKM.Cypher.SecretKey, bobKM.Cypher.PublicKey)
	must(err)

	var material []byte
	material = append(material, es...)
	material = append(material, ss...)
	material = append(material, []byte("VAULTYS_DHIES_V2")...)
	material = append(material, ePub...)
	material = append(material, aliceKM.Cypher.PublicKey...)
	material = append(material, bobKM.Cypher.PublicKey...)
	sum := sha512.Sum512(material)
	var k [32]byte
	copy(k[:], sum[:32])

	message := append([]byte{0x02}, nonce[:]...)
	message = append(message, ePub...)
	message = secretbox.Seal(message, plaintext, &nonce, &k)

	// Validate with the real implementation.
	decrypted, err := keymanager.DHIESDecryptV2(bobKM.Cypher.SecretKey, bobKM.Cypher.PublicKey, aliceKM.Cypher.PublicKey, message)
	must(err)
	if string(decrypted) != string(plaintext) {
		panic("decrypted plaintext does not match original")
	}
	prod, err := alice.DHIESEncrypt(plaintext, bob)
	must(err)
	if _, err := bob.DHIESDecrypt(prod, alice); err != nil {
		panic("production round trip failed")
	}
	tampered := append([]byte{}, message...)
	tampered[len(tampered)-1] ^= 0xff
	_, tamperErr := bob.DHIESDecrypt(tampered, alice)

	out := map[string]interface{}{
		"description": "Deterministic DHIES v2 reference vector (fixed ephemeral key and nonce). Validated with the real DHIESDecryptV2.",
		"wireFormat":  "0x02 || nonce(24) || ephemeralPublicKey(32) || secretbox(plaintext) (len(plaintext)+16)",
		"kdf":         "es = X25519(e_sk, R_pk); ss = X25519(S_sk, R_pk); k = SHA-512(es || ss || \"VAULTYS_DHIES_V2\" || e_pk || S_pk || R_pk)[0:32]",
		"identities": map[string]interface{}{
			"alice": map[string]string{"entropyHex": hex.EncodeToString(aliceEntropy), "cypherPublicKeyHex": hex.EncodeToString(aliceKM.Cypher.PublicKey)},
			"bob":   map[string]string{"entropyHex": hex.EncodeToString(bobEntropy), "cypherPublicKeyHex": hex.EncodeToString(bobKM.Cypher.PublicKey)},
		},
		"inputs": map[string]string{
			"plaintextUtf8":       string(plaintext),
			"ephemeralPrivateHex": hex.EncodeToString(ePriv),
			"ephemeralPublicHex":  hex.EncodeToString(ePub),
			"nonceHex":            hex.EncodeToString(nonce[:]),
		},
		"derived": map[string]string{
			"esHex": hex.EncodeToString(es),
			"ssHex": hex.EncodeToString(ss),
			"kHex":  hex.EncodeToString(k[:]),
		},
		"output": map[string]interface{}{
			"messageHex":              hex.EncodeToString(message),
			"messageLength":           len(message),
			"tamperedMessageRejected": tamperErr != nil,
		},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(out))
}
