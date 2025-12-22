package keymanager

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEd25519Manager_Generate(t *testing.T) {
	km, err := GenerateInternal()
	if err != nil {
		t.Fatal(err)
	}

	if km.Version != 1 {
		t.Error("Version should be 1")
	}
	if km.Capability != "private" {
		t.Error("Should have private capability")
	}
	if len(km.Signer.PublicKey) != 32 {
		t.Error("Invalid signer public key length")
	}
	if len(km.Cypher.PublicKey) != 32 {
		t.Error("Invalid cypher public key length")
	}
}

func TestEd25519Manager_SignVerify(t *testing.T) {
	km, _ := GenerateInternal()
	data := []byte("test data")

	sig, err := km.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(sig) != 64 {
		t.Error("Invalid signature length")
	}

	// Verify with same manager
	if err := km.Verify(data, sig); err != nil {
		t.Error("Self verification failed")
	}

	// Wrong data should fail
	if err := km.Verify([]byte("wrong"), sig); err == nil {
		t.Error("Should fail with wrong data")
	}
}

func TestEd25519Manager_DiffieHellman(t *testing.T) {
	alice, _ := GenerateInternal()
	bob, _ := GenerateInternal()

	// Alice computes shared secret with Bob
	sharedAlice, err := alice.DiffieHellman(bob.Cypher.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Bob computes shared secret with Alice
	sharedBob, err := bob.DiffieHellman(alice.Cypher.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Shared secrets should match
	if !bytes.Equal(sharedAlice, sharedBob) {
		t.Error("Shared secrets don't match")
	}

	if len(sharedAlice) != 32 {
		t.Error("Invalid shared secret length")
	}
}

func TestEd25519Manager_HMAC(t *testing.T) {
	km, _ := GenerateInternal()

	hmac1, err := km.HMAC("test message")
	if err != nil {
		t.Fatal(err)
	}

	// Same message should give same HMAC
	hmac2, _ := km.HMAC("test message")
	if !bytes.Equal(hmac1, hmac2) {
		t.Error("HMAC not deterministic")
	}

	// Different message should give different HMAC
	hmac3, _ := km.HMAC("different")
	if bytes.Equal(hmac1, hmac3) {
		t.Error("Different messages should give different HMACs")
	}
}

func TestEd25519Manager_FromEntropy(t *testing.T) {
	entropy := make([]byte, 32)
	for i := range entropy {
		entropy[i] = byte(i)
	}

	km1, err := CreateFromEntropyInternal(entropy)
	if err != nil {
		t.Fatal(err)
	}

	km2, err := CreateFromEntropyInternal(entropy)
	if err != nil {
		t.Fatal(err)
	}

	// Same entropy should give same keys
	if !bytes.Equal(km1.Signer.PublicKey, km2.Signer.PublicKey) {
		t.Error("Same entropy should give same signer key")
	}
	if !bytes.Equal(km1.Cypher.PublicKey, km2.Cypher.PublicKey) {
		t.Error("Same entropy should give same cypher key")
	}
}

func TestEd25519Manager_Serialization(t *testing.T) {
	original, _ := GenerateInternal()

	// Test ToBytes (public serialization)
	pubBytes := original.ToBytes()
	restored, err := FromIDInternal(pubBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Should have public capability
	if restored.Capability != "public" {
		t.Error("FromID should create public-only manager")
	}

	// Public keys should match
	if !bytes.Equal(original.Signer.PublicKey, restored.Signer.PublicKey) {
		t.Error("Signer public key not preserved")
	}
	if !bytes.Equal(original.Cypher.PublicKey, restored.Cypher.PublicKey) {
		t.Error("Cypher public key not preserved")
	}

	// Should not have private keys
	if len(restored.Signer.SecretKey) != 0 {
		t.Error("Public manager shouldn't have signer secret key")
	}
	if len(restored.Cypher.SecretKey) != 0 {
		t.Error("Public manager shouldn't have cypher secret key")
	}
}

func TestEd25519Manager_SecretSerialization(t *testing.T) {
	original, _ := GenerateInternal()

	// Test GetSecret (private serialization)
	secret, err := original.GetSecret()
	if err != nil {
		t.Fatal(err)
	}

	restored, err := FromSecretInternal(secret)
	if err != nil {
		t.Fatal(err)
	}

	// Should have private capability
	if restored.Capability != "private" {
		t.Error("FromSecret should restore private capability")
	}

	// Keys should match
	if !bytes.Equal(original.Signer.PublicKey, restored.Signer.PublicKey) {
		t.Error("Signer public key not preserved")
	}
	if !bytes.Equal(original.Signer.SecretKey, restored.Signer.SecretKey) {
		t.Error("Signer secret key not preserved")
	}
	if !bytes.Equal(original.Cypher.PublicKey, restored.Cypher.PublicKey) {
		t.Error("Cypher public key not preserved")
	}
	if !bytes.Equal(original.Cypher.SecretKey, restored.Cypher.SecretKey) {
		t.Error("Cypher secret key not preserved")
	}

	// Should be able to sign
	data := []byte("test")
	sig1, _ := original.Sign(data)
	sig2, _ := restored.Sign(data)
	if !bytes.Equal(sig1, sig2) {
		t.Error("Signatures should match")
	}
}

func TestEd25519Manager_PublicOnlyCannotSign(t *testing.T) {
	km, _ := GenerateInternal()
	pubBytes := km.ToBytes()
	publicKm, _ := FromIDInternal(pubBytes)

	// Should not be able to sign
	_, err := publicKm.Sign([]byte("test"))
	if err == nil {
		t.Error("Public-only manager should not be able to sign")
	}

	// Should not be able to do DH
	_, err = publicKm.DiffieHellman([]byte{1, 2, 3})
	if err == nil {
		t.Error("Public-only manager should not be able to do DH")
	}

	// Should not be able to compute HMAC
	_, err = publicKm.HMAC("test")
	if err == nil {
		t.Error("Public-only manager should not be able to compute HMAC")
	}

	// Should not be able to get secret
	_, err = publicKm.GetSecret()
	if err == nil {
		t.Error("Public-only manager should not have secret")
	}
}

func TestEd25519Manager_PublicOnlyCanVerify(t *testing.T) {
	km, _ := GenerateInternal()
	data := []byte("test data")
	sig, _ := km.Sign(data)

	// Create public-only version
	pubBytes := km.ToBytes()
	publicKm, _ := FromIDInternal(pubBytes)

	// Should be able to verify
	if err := publicKm.Verify(data, sig); err != nil {
		t.Error("Public-only manager should be able to verify")
	}

	// Should fail with wrong signature
	wrongSig := make([]byte, len(sig))
	copy(wrongSig, sig)
	wrongSig[0] ^= 0xFF
	if err := publicKm.Verify(data, wrongSig); err == nil {
		t.Error("Should fail with wrong signature")
	}
}

func TestEd25519Manager_Version(t *testing.T) {
	km, _ := GenerateInternal()

	// Default version should be 1
	if km.GetVersion() != 1 {
		t.Errorf("Default version should be 1, got %d", km.GetVersion())
	}

	// Set to version 0
	err := km.SetVersion(0)
	if err != nil {
		t.Errorf("Failed to set version to 0: %v", err)
	}

	if km.GetVersion() != 0 {
		t.Errorf("Version should be 0, got %d", km.GetVersion())
	}

	// Set back to version 1
	err = km.SetVersion(1)
	if err != nil {
		t.Errorf("Failed to set version to 1: %v", err)
	}

	if km.GetVersion() != 1 {
		t.Errorf("Version should be 1, got %d", km.GetVersion())
	}

	// Invalid version should fail
	err = km.SetVersion(2)
	if err == nil {
		t.Error("Should fail with invalid version")
	}
}

func TestEd25519Manager_GetAuthType(t *testing.T) {
	km, _ := GenerateInternal()
	if km.GetAuthType() != "Ed25519VerificationKey2020" {
		t.Errorf("Wrong auth type: %s", km.GetAuthType())
	}
}

func TestEd25519Manager_GetEncType(t *testing.T) {
	km, _ := GenerateInternal()
	if km.GetEncType() != "X25519KeyAgreementKey2019" {
		t.Errorf("Wrong enc type: %s", km.GetEncType())
	}
}

func TestEd25519Manager_FixedEntropy(t *testing.T) {
	// Test with known entropy to verify deterministic key generation
	entropyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	entropy, _ := hex.DecodeString(entropyHex)

	km, err := CreateFromEntropyInternal(entropy)
	if err != nil {
		t.Fatal(err)
	}

	// These values should be deterministic
	signerPK := hex.EncodeToString(km.Signer.PublicKey)
	cypherPK := hex.EncodeToString(km.Cypher.PublicKey)

	// Recreate and verify same results
	km2, _ := CreateFromEntropyInternal(entropy)
	if hex.EncodeToString(km2.Signer.PublicKey) != signerPK {
		t.Error("Signer public key not deterministic")
	}
	if hex.EncodeToString(km2.Cypher.PublicKey) != cypherPK {
		t.Error("Cypher public key not deterministic")
	}
}

func TestEd25519Manager_CleanSecureData(t *testing.T) {
	km, _ := GenerateInternal()

	// Store original keys
	signerSecret := make([]byte, len(km.Signer.SecretKey))
	cypherSecret := make([]byte, len(km.Cypher.SecretKey))
	copy(signerSecret, km.Signer.SecretKey)
	copy(cypherSecret, km.Cypher.SecretKey)

	// Clean secure data
	km.CleanSecureData()

	// Keys should be nil
	if km.Signer.SecretKey != nil {
		t.Error("Signer secret key should be nil after cleanup")
	}
	if km.Cypher.SecretKey != nil {
		t.Error("Cypher secret key should be nil after cleanup")
	}
	if km.Entropy != nil {
		t.Error("Entropy should be nil after cleanup")
	}
}

func TestEd25519Manager_InterfaceCompliance(t *testing.T) {
	// Verify that Ed25519Manager implements KeyManager interface
	var _ KeyManager = (*Ed25519Manager)(nil)

	// Test through interface
	var km KeyManager
	km, err := Generate()
	if err != nil {
		t.Fatal(err)
	}

	// Test all interface methods
	_ = km.GetPublicKey()
	_ = km.GetCypherPublicKey()
	_ = km.GetCapability()
	_ = km.GetAuthType()
	_ = km.GetEncType()
	_ = km.GetVersion()
	_ = km.ToBytes()

	data := []byte("test")
	sig, err := km.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	err = km.Verify(data, sig)
	if err != nil {
		t.Fatal(err)
	}
}
